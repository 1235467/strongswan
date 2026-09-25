/*
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

/**
 * Shadowsocks UDP relay codec.
 *
 * Wraps IKE/ESP UDP datagrams in Shadowsocks UDP relay format so they can be
 * transported via a Shadowsocks server.  Wire format follows SIP004/SIP007
 * (AEAD ciphers) as implemented in shadowsocks-c (aead.c); SIP022
 * (2022-blake3-*) is a TODO.
 *
 * @defgroup socket_shadowsocks_ss socket_shadowsocks_ss
 * @{ @ingroup socket_shadowsocks
 */

#ifndef SOCKET_SHADOWSOCKS_SS_H_
#define SOCKET_SHADOWSOCKS_SS_H_

typedef struct ss_ctx_t ss_ctx_t;

#include <library.h>
#include <networking/host.h>

/**
 * Shadowsocks UDP relay context.
 */
struct ss_ctx_t {

	/**
	 * Encrypt a payload for the given target and wrap it in a Shadowsocks
	 * UDP packet for the configured server.
	 *
	 * @param dst		original packet destination (embedded as target)
	 * @param payload	payload to encrypt
	 * @param out		allocated encrypted packet: salt || ct || tag
	 * @return			TRUE if encryption succeeded
	 */
	bool (*encrypt)(ss_ctx_t *this, host_t *dst, chunk_t payload,
					chunk_t *out);

	/**
	 * Decrypt a Shadowsocks UDP packet received from the server.
	 *
	 * @param in		received packet data: salt || ct || tag
	 * @param src		reconstructed source address (embedded target)
	 * @param payload	allocated decrypted payload
	 * @return			TRUE if decryption succeeded
	 */
	bool (*decrypt)(ss_ctx_t *this, chunk_t in, host_t **src,
					chunk_t *payload);

	/**
	 * Check whether the given address is the Shadowsocks server.
	 */
	bool (*is_from_server)(ss_ctx_t *this, host_t *src);

	/**
	 * Get the Shadowsocks server address (internal data).
	 */
	host_t *(*get_server)(ss_ctx_t *this);

	/**
	 * Destroy the context.
	 */
	void (*destroy)(ss_ctx_t *this);
};

/**
 * Create a Shadowsocks UDP relay context.
 *
 * @param server	server hostname or IP address
 * @param port		server port
 * @param method	cipher method (e.g. "aes-128-gcm")
 * @param password	password (classic methods) or base64 PSK (2022-*)
 * @return			context, NULL on failure
 */
ss_ctx_t *ss_ctx_create(char *server, uint16_t port, char *method,
						char *password);

#endif /** SOCKET_SHADOWSOCKS_SS_H_ @}*/
