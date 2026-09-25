/*
 * Shadowsocks UDP relay codec.
 *
 * Implements the Shadowsocks AEAD UDP packet format (SIP004/SIP007) used by
 * shadowsocks-c/shadowsocks-libev and sing-box, so IKEv2/ESP traffic can be
 * relayed through a Shadowsocks server:
 *
 *   [salt][AEAD(subkey, nonce=0, [ATYP|addr|port] || payload)][tag]
 *
 * Key derivation for classic AEAD methods:
 *   master key = EVP_BytesToKey(MD5, password, key_len)
 *   subkey     = HKDF-SHA1(master_key, salt, "ss-subkey")
 *
 * SIP022 (2022-blake3-*) methods are recognized but not yet implemented; they
 * use a different key scheme (base64 PSK) and a session-based packet format.
 *
 * The AEAD tag size is always 16 bytes.  The nonce for UDP is all zeroes
 * (a fresh random salt is used for every datagram).
 *
 * This file was written following the implementation in shadowsocks-c
 * (src/aead.c), which is GPLv3.
 *
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

#include "socket_shadowsocks_ss.h"

#include <string.h>
#include <daemon.h>
#include <threading/mutex.h>

/** MD5 output length for EVP_BytesToKey */
#define MD5_LEN			16
/** SHA-1 output length (HKDF PRK) */
#define SHA1_LEN		20
/** AEAD tag length used by Shadowsocks */
#define SS_TAG_LEN		16
/** implicit salt appended to the AEAD key (strongSwan RFC 4106 convention) */
#define SS_AEAD_SALT_LEN	4
/** explicit IV passed to the AEAD (nonce = salt || iv = 12 zero bytes) */
#define SS_AEAD_IV_LEN		8
/** HKDF info string for per-packet subkeys */
#define SS_SUBKEY_INFO		"ss-subkey"

typedef struct private_ss_ctx_t private_ss_ctx_t;

/**
 * Supported cipher methods.
 */
typedef enum ss_cipher_id_t {
	SS_CIPHER_AES_128_GCM,
	SS_CIPHER_AES_192_GCM,
	SS_CIPHER_AES_256_GCM,
	SS_CIPHER_CHACHA20_IETF_POLY1305,
	/* SIP022 ciphers, not yet implemented */
	SS_CIPHER_AES_128_GCM_2022,
	SS_CIPHER_AES_256_GCM_2022,
	SS_CIPHER_CHACHA20_POLY1305_2022,
} ss_cipher_id_t;

typedef struct ss_cipher_t {
	ss_cipher_id_t id;
	char *name;
	size_t key_len;
	encryption_algorithm_t encr;
	bool is2022;
} ss_cipher_t;

static const ss_cipher_t ss_ciphers[] = {
	{ SS_CIPHER_AES_128_GCM,           "aes-128-gcm",                  16,
	  ENCR_AES_GCM_ICV16, FALSE },
	{ SS_CIPHER_AES_192_GCM,           "aes-192-gcm",                  24,
	  ENCR_AES_GCM_ICV16, FALSE },
	{ SS_CIPHER_AES_256_GCM,           "aes-256-gcm",                  32,
	  ENCR_AES_GCM_ICV16, FALSE },
	{ SS_CIPHER_CHACHA20_IETF_POLY1305, "chacha20-ietf-poly1305",      32,
	  ENCR_CHACHA20_POLY1305, FALSE },
	{ SS_CIPHER_AES_128_GCM_2022,      "2022-blake3-aes-128-gcm",      16,
	  ENCR_AES_GCM_ICV16, TRUE },
	{ SS_CIPHER_AES_256_GCM_2022,      "2022-blake3-aes-256-gcm",      32,
	  ENCR_AES_GCM_ICV16, TRUE },
	{ SS_CIPHER_CHACHA20_POLY1305_2022, "2022-blake3-chacha20-poly1305", 32,
	  ENCR_CHACHA20_POLY1305, TRUE },
};

/**
 * Private data.
 */
struct private_ss_ctx_t {

	/**
	 * Public interface.
	 */
	ss_ctx_t public;

	/**
	 * Shadowsocks server address.
	 */
	host_t *server;

	/**
	 * Cipher specification.
	 */
	const ss_cipher_t *cipher;

	/**
	 * Master key (classic methods) or parsed PSK (2022 methods).
	 */
	chunk_t key;

	/**
	 * RNG for per-packet salts.
	 */
	rng_t *rng;

	/**
	 * Serialize encrypt/decrypt (per-packet AEAD contexts are created on the
	 * fly, but session state for 2022 ciphers will need this).
	 */
	mutex_t *mutex;
};

/**
 * Derive a key from a password using the EVP_BytesToKey() scheme with MD5,
 * as used by classic Shadowsocks AEAD methods.
 */
static bool evp_bytes_to_key(chunk_t password, uint8_t *key, size_t key_len)
{
	hasher_t *hasher;
	uint8_t md[MD5_LEN];
	size_t done = 0;
	bool have_md = FALSE;

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	if (!hasher)
	{
		DBG1(DBG_NET, "MD5 hasher unavailable for Shadowsocks key derivation");
		return FALSE;
	}
	while (done < key_len)
	{
		if (have_md &&
			!hasher->get_hash(hasher, chunk_create(md, MD5_LEN), NULL))
		{
			hasher->destroy(hasher);
			return FALSE;
		}
		if (!hasher->get_hash(hasher, password, md))
		{
			hasher->destroy(hasher);
			return FALSE;
		}
		memcpy(key + done, md, min(key_len - done, MD5_LEN));
		done += MD5_LEN;
		have_md = TRUE;
	}
	hasher->destroy(hasher);
	return TRUE;
}

/**
 * HKDF-SHA1(key, salt, info) -> okm, per RFC 5869, implemented on a generic
 * HMAC-SHA1 PRF.
 */
static bool hkdf_sha1(chunk_t ikm, chunk_t salt, chunk_t info,
					uint8_t *okm, size_t okm_len)
{
	prf_t *prf;
	uint8_t prk[SHA1_LEN], t[SHA1_LEN];
	size_t t_len = 0;
	uint8_t c = 0;

	prf = lib->crypto->create_prf(lib->crypto, PRF_HMAC_SHA1);
	if (!prf)
	{
		DBG1(DBG_NET, "HMAC-SHA1 PRF unavailable for Shadowsocks subkey "
			 "derivation");
		return FALSE;
	}
	/* extract: PRK = HMAC(salt, IKM) */
	if (!prf->set_key(prf, salt) ||
		!prf->get_bytes(prf, ikm, prk))
	{
		prf->destroy(prf);
		return FALSE;
	}
	/* expand: T(n) = HMAC(PRK, T(n-1) | info | n) */
	if (!prf->set_key(prf, chunk_create(prk, SHA1_LEN)))
	{
		prf->destroy(prf);
		return FALSE;
	}
	while (okm_len)
	{
		uint8_t seed[t_len + info.len + 1];
		size_t n;

		memcpy(seed, t, t_len);
		memcpy(seed + t_len, info.ptr, info.len);
		seed[t_len + info.len] = ++c;
		if (!prf->get_bytes(prf, chunk_create(seed, sizeof(seed)), t))
		{
			prf->destroy(prf);
			return FALSE;
		}
		t_len = SHA1_LEN;
		n = min(SHA1_LEN, okm_len);
		memcpy(okm, t, n);
		okm += n;
		okm_len -= n;
	}
	prf->destroy(prf);
	return TRUE;
}

/**
 * Encode a host_t as a SOCKS5-style address header: ATYP | ADDR | PORT.
 */
static chunk_t encode_addr(host_t *host)
{
	uint8_t atyp;
	chunk_t addr, out;
	uint16_t port;

	switch (host->get_family(host))
	{
		case AF_INET:
			atyp = 0x01;
			break;
		case AF_INET6:
			atyp = 0x04;
			break;
		default:
			return chunk_empty;
	}
	addr = host->get_address(host);
	out = chunk_alloc(1 + addr.len + 2);
	out.ptr[0] = atyp;
	memcpy(out.ptr + 1, addr.ptr, addr.len);
	port = htons(host->get_port(host));
	memcpy(out.ptr + 1 + addr.len, &port, 2);
	return out;
}

/**
 * Parse a SOCKS5-style address header, return the host and rest as payload.
 */
static host_t *decode_addr(chunk_t data, chunk_t *payload)
{
	int family;
	size_t addr_len;
	host_t *host;
	uint16_t port;
	chunk_t addr;

	if (data.len < 1)
	{
		return NULL;
	}
	switch (data.ptr[0])
	{
		case 0x01:
			family = AF_INET;
			addr_len = 4;
			break;
		case 0x04:
			family = AF_INET6;
			addr_len = 16;
			break;
		case 0x03:
			/* we only ever send literal IP targets; the server echoes them
			 * back, so domain names are not expected */
			DBG2(DBG_NET, "domain name target in Shadowsocks UDP reply not "
				 "supported");
			return NULL;
		default:
			return NULL;
	}
	if (data.len < 1 + addr_len + 2)
	{
		return NULL;
	}
	addr = chunk_create(data.ptr + 1, addr_len);
	memcpy(&port, data.ptr + 1 + addr_len, 2);
	host = host_create_from_chunk(family, addr, ntohs(port));
	if (!host)
	{
		return NULL;
	}
	*payload = chunk_skip(data, 1 + addr_len + 2);
	return host;
}

/**
 * Create an AEAD transform for the per-packet subkey.
 */
static aead_t *create_aead(private_ss_ctx_t *this, chunk_t subkey)
{
	aead_t *aead;
	uint8_t keybuf[this->cipher->key_len + SS_AEAD_SALT_LEN];

	/* strongSwan's AEAD convention (RFC 4106): key = cipher key || implicit
	 * salt, nonce = salt || explicit IV.  Shadowsocks uses an all-zero 12
	 * byte nonce, so salt and IV are all zeroes. */
	aead = lib->crypto->create_aead(lib->crypto, this->cipher->encr,
									this->cipher->key_len, SS_AEAD_SALT_LEN);
	if (!aead)
	{
		return NULL;
	}
	memcpy(keybuf, subkey.ptr, this->cipher->key_len);
	memset(keybuf + this->cipher->key_len, 0, SS_AEAD_SALT_LEN);
	if (!aead->set_key(aead, chunk_create(keybuf, sizeof(keybuf))))
	{
		aead->destroy(aead);
		return NULL;
	}
	return aead;
}

/**
 * Encrypt plain using the classic AEAD UDP format.
 */
static bool encrypt_classic(private_ss_ctx_t *this, host_t *dst,
							chunk_t payload, chunk_t *out)
{
	chunk_t addr, plain, salt, subkey, ct;
	uint8_t iv[SS_AEAD_IV_LEN] = {};
	aead_t *aead;
	bool success = FALSE;

	addr = encode_addr(dst);
	if (!addr.ptr)
	{
		return FALSE;
	}
	plain = chunk_cat("cc", addr, payload);
	chunk_free(&addr);

	salt = chunk_alloc(this->cipher->key_len);
	subkey = chunk_alloc(this->cipher->key_len);
	if (!this->rng->get_bytes(this->rng, salt.len, salt.ptr) ||
		!hkdf_sha1(this->key, salt,
				   chunk_from_str(SS_SUBKEY_INFO), subkey.ptr, subkey.len))
	{
		goto out;
	}
	aead = create_aead(this, subkey);
	if (!aead)
	{
		goto out;
	}
	success = aead->encrypt(aead, plain, chunk_empty,
							chunk_create(iv, sizeof(iv)), &ct);
	aead->destroy(aead);
	if (success)
	{
		*out = chunk_cat("mm", salt, ct);
	}
out:
	chunk_clear(&subkey);
	if (!success)
	{
		chunk_free(&salt);
	}
	chunk_clear(&plain);
	return success;
}

/**
 * Decrypt a classic AEAD UDP packet.
 */
static bool decrypt_classic(private_ss_ctx_t *this, chunk_t in,
							host_t **src, chunk_t *payload)
{
	chunk_t salt, subkey, ct, plain;
	host_t *host;
	uint8_t iv[SS_AEAD_IV_LEN] = {};
	aead_t *aead;
	bool success = FALSE;

	if (in.len < this->cipher->key_len + SS_TAG_LEN + 1 + 4 + 2)
	{
		return FALSE;
	}
	salt = chunk_create(in.ptr, this->cipher->key_len);
	ct = chunk_skip(in, this->cipher->key_len);

	subkey = chunk_alloc(this->cipher->key_len);
	if (!hkdf_sha1(this->key, salt, chunk_from_str(SS_SUBKEY_INFO),
				   subkey.ptr, subkey.len))
	{
		goto out;
	}
	aead = create_aead(this, subkey);
	if (!aead)
	{
		goto out;
	}
	success = aead->decrypt(aead, ct, chunk_empty,
							chunk_create(iv, sizeof(iv)), &plain);
	aead->destroy(aead);
	if (success)
	{
		host = decode_addr(plain, payload);
		if (host)
		{
			*src = host;
			memmove(plain.ptr, payload->ptr, payload->len);
			plain.len = payload->len;
			*payload = plain;
		}
		else
		{
			chunk_free(&plain);
			success = FALSE;
		}
	}
out:
	chunk_clear(&subkey);
	return success;
}

METHOD(ss_ctx_t, encrypt, bool,
	private_ss_ctx_t *this, host_t *dst, chunk_t payload, chunk_t *out)
{
	bool success;

	this->mutex->lock(this->mutex);
	if (this->cipher->is2022)
	{
		/* TODO: implement SIP022 UDP session format (aead2022_udp.c),
		 * warning was already logged during context creation */
		success = FALSE;
	}
	else
	{
		success = encrypt_classic(this, dst, payload, out);
	}
	this->mutex->unlock(this->mutex);
	return success;
}

METHOD(ss_ctx_t, decrypt, bool,
	private_ss_ctx_t *this, chunk_t in, host_t **src, chunk_t *payload)
{
	bool success;

	this->mutex->lock(this->mutex);
	if (this->cipher->is2022)
	{
		success = FALSE;
	}
	else
	{
		success = decrypt_classic(this, in, src, payload);
	}
	this->mutex->unlock(this->mutex);
	return success;
}

METHOD(ss_ctx_t, is_from_server, bool,
	private_ss_ctx_t *this, host_t *src)
{
	return src && this->server->equals(this->server, src);
}

METHOD(ss_ctx_t, get_server, host_t*,
	private_ss_ctx_t *this)
{
	return this->server;
}

METHOD(ss_ctx_t, destroy, void,
	private_ss_ctx_t *this)
{
	DESTROY_IF(this->server);
	chunk_clear(&this->key);
	DESTROY_IF(this->rng);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Find a cipher by name.
 */
static const ss_cipher_t *find_cipher(char *method)
{
	int i;

	for (i = 0; i < countof(ss_ciphers); i++)
	{
		if (streq(method, ss_ciphers[i].name))
		{
			return &ss_ciphers[i];
		}
	}
	return NULL;
}

/*
 * Described in header.
 */
ss_ctx_t *ss_ctx_create(char *server, uint16_t port, char *method,
						char *password)
{
	private_ss_ctx_t *this;
	host_t *host;
	chunk_t psk;

	if (!server || !port || !method || !password)
	{
		DBG1(DBG_NET, "incomplete Shadowsocks configuration (server, port, "
			 "method and password are required)");
		return NULL;
	}
	if (!find_cipher(method))
	{
		DBG1(DBG_NET, "unsupported Shadowsocks method '%s'", method);
		return NULL;
	}

	host = host_create_from_string(server, port);
	if (!host)
	{
		host = host_create_from_dns(server, AF_UNSPEC, port);
	}
	if (!host)
	{
		DBG1(DBG_NET, "failed to resolve Shadowsocks server '%s'", server);
		return NULL;
	}

	INIT(this,
		.public = {
			.encrypt = _encrypt,
			.decrypt = _decrypt,
			.is_from_server = _is_from_server,
			.get_server = _get_server,
			.destroy = _destroy,
		},
		.server = host,
		.cipher = find_cipher(method),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (this->cipher->is2022)
	{
		DBG1(DBG_NET, "Shadowsocks method '%s' (SIP022) is not yet "
			 "implemented, IKE traffic will be dropped", method);
		/* SIP022 uses a base64 encoded PSK of exactly key_len bytes instead
		 * of a password (same convention as shadowsocks-c -k) */
		psk = chunk_from_base64(chunk_from_str(password), NULL);
		if (psk.len != this->cipher->key_len)
		{
			DBG1(DBG_NET, "invalid base64 PSK for Shadowsocks method '%s', "
				 "expected %d bytes", method, this->cipher->key_len);
			chunk_free(&psk);
			destroy(this);
			return NULL;
		}
		this->key = psk;
	}
	else
	{
		this->key = chunk_alloc(this->cipher->key_len);
		if (!evp_bytes_to_key(chunk_from_str(password), this->key.ptr,
							  this->key.len))
		{
			destroy(this);
			return NULL;
		}
	}

	this->rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!this->rng)
	{
		DBG1(DBG_NET, "no strong RNG available for Shadowsocks salts");
		destroy(this);
		return NULL;
	}
	return &this->public;
}
