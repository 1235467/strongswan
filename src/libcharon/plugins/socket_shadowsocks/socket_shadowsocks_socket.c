/*
 * Socket implementation relaying IKE/ESP UDP traffic through a Shadowsocks
 * server.
 *
 * This is a decorator over the default socket implementation: the inner
 * socket (socket_default_socket.c, compiled in via socket_shadowsocks_inner.c)
 * provides the actual UDP sockets, port binding, packet info handling and
 * kernel bypass hooks.  This wrapper transparently encrypts outbound packets
 * into Shadowsocks UDP relay format (embedding the original destination) and
 * decrypts inbound packets received from the Shadowsocks server (restoring
 * the original source address).
 *
 * charon keeps talking to the real VPN gateway address; only the UDP wire
 * image changes.  IKE identity checks, NAT-T, MOBIKE and the ESP-in-UDP
 * datapath are unaffected.
 *
 * Configuration (strongswan.conf):
 *
 *   charon.plugins.socket-shadowsocks {
 *       server = <hostname|IP>     # Shadowsocks server
 *       port = <port>              # Shadowsocks server port
 *       method = aes-128-gcm       # cipher method
 *       password = <password>      # password (or base64 PSK for 2022-*)
 *   }
 *
 * If "server" is not set the socket behaves exactly like socket-default.
 * If it is set but the configuration is invalid, packets are dropped
 * (fail closed).
 *
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

#include "socket_shadowsocks_socket.h"
#include "socket_shadowsocks_ss.h"

#include <string.h>
#include <daemon.h>
#include <threading/mutex.h>

typedef struct private_socket_shadowsocks_socket_t
		private_socket_shadowsocks_socket_t;

/**
 * The inner socket implementation (socket_default_socket.c compiled in with
 * a renamed public symbol by socket_shadowsocks_inner.c).
 */
socket_t *ss_inner_socket_create(void);

/**
 * Private data.
 */
struct private_socket_shadowsocks_socket_t {

	/**
	 * Public interface.
	 */
	socket_shadowsocks_socket_t public;

	/**
	 * Real socket implementation.
	 */
	socket_t *inner;

	/**
	 * Shadowsocks context, NULL if disabled.
	 */
	ss_ctx_t *ss;

	/**
	 * Configuration the context was created from, for change detection
	 * (NULL fields mean unset, compared exactly so every byte counts).
	 */
	char *cfg_server;
	int cfg_port;
	char *cfg_method;
	char *cfg_password;

	/**
	 * TRUE if SS is configured but context creation failed (fail closed).
	 */
	bool cfg_failed;

	/**
	 * Next time (monotonic) the settings are re-evaluated.  Refreshing is
	 * rate-limited: re-reading all settings on every packet costs a rwlock
	 * and a tree walk per key.
	 */
	time_t next_refresh;

	/**
	 * Serializes configuration updates (send and receive run on different
	 * threads).
	 */
	mutex_t *mutex;
};

/**
 * Interval in seconds between lazy configuration checks.
 */
#define CFG_REFRESH_INTERVAL 1

/**
 * (Re-)load the Shadowsocks configuration if it changed.  The socket is
 * instantiated during plugin load, but the per-connection settings only
 * arrive later, so the configuration is evaluated lazily here.
 */
static void update_config(private_socket_shadowsocks_socket_t *this)
{
	char *server, *method, *password;
	ss_ctx_t *ctx = NULL;
	bool pending = FALSE, failed = FALSE;
	int port;

	this->mutex->lock(this->mutex);
	if (time_monotonic(NULL) < this->next_refresh)
	{	/* throttle: an uncontended lock is still far cheaper than
		 * re-reading all settings on every packet */
		this->mutex->unlock(this->mutex);
		return;
	}
	while (TRUE)
	{
		/* the settings are read under the mutex so a snapshot based on
		 * older values can not overwrite a context another thread already
		 * installed */
		server = lib->settings->get_str(lib->settings,
					"%s.plugins.socket-shadowsocks.server", NULL, lib->ns);
		port = lib->settings->get_int(lib->settings,
					"%s.plugins.socket-shadowsocks.port", 0, lib->ns);
		method = lib->settings->get_str(lib->settings,
					"%s.plugins.socket-shadowsocks.method", NULL, lib->ns);
		password = lib->settings->get_str(lib->settings,
					"%s.plugins.socket-shadowsocks.password", NULL, lib->ns);

		if (streq(this->cfg_server, server) && this->cfg_port == port &&
			streq(this->cfg_method, method) &&
			streq(this->cfg_password, password))
		{	/* unchanged, or still the snapshot we just resolved for:
			 * install the result (NULL ctx disables the relay) */
			if (pending)
			{
				DESTROY_IF(this->ss);
				this->ss = ctx;
				this->cfg_failed = failed;
				if (ctx)
				{
					DBG1(DBG_NET, "relaying IKE/ESP traffic via Shadowsocks"
						 " server %#H (%s)", this->ss->get_server(this->ss),
						 method);
				}
				else if (failed)
				{
					DBG1(DBG_NET, "invalid Shadowsocks configuration, IKE "
						 "traffic will be dropped");
				}
			}
			this->next_refresh = time_monotonic(NULL) + CFG_REFRESH_INTERVAL;
			this->mutex->unlock(this->mutex);
			return;
		}
		/* remember the snapshot we are about to resolve for */
		free(this->cfg_server);
		this->cfg_server = server ? strdup(server) : NULL;
		this->cfg_port = port;
		free(this->cfg_method);
		this->cfg_method = method ? strdup(method) : NULL;
		if (this->cfg_password)
		{
			memwipe(this->cfg_password, strlen(this->cfg_password));
			free(this->cfg_password);
		}
		this->cfg_password = password ? strdup(password) : NULL;
		this->mutex->unlock(this->mutex);

		/* context creation may block on DNS resolution, keep the mutex
		 * free so other packet threads are not stalled */
		DESTROY_IF(ctx);
		ctx = NULL;
		failed = FALSE;
		if (server && *server)
		{
			if (port < 1 || port > 65535)
			{
				DBG1(DBG_NET, "Shadowsocks server port %d out of range",
					 port);
			}
			else
			{
				ctx = ss_ctx_create(server, (uint16_t)port, method,
									password);
			}
			failed = !ctx;
		}
		pending = TRUE;
		this->mutex->lock(this->mutex);
	}
}

METHOD(socket_t, receiver, status_t,
	private_socket_shadowsocks_socket_t *this, packet_t **packet)
{
	packet_t *pkt;
	host_t *src;
	chunk_t payload;
	status_t status;

	while (TRUE)
	{
		update_config(this);
		status = this->inner->receive(this->inner, &pkt);
		if (status != SUCCESS)
		{
			return status;
		}
		this->mutex->lock(this->mutex);
		if (this->cfg_failed)
		{	/* Shadowsocks configured but unusable: drop, never accept
			 * unauthenticated plaintext (fail closed) */
			this->mutex->unlock(this->mutex);
			DBG2(DBG_NET, "discarding packet from %#H while Shadowsocks "
				 "configuration is invalid", pkt->get_source(pkt));
			pkt->destroy(pkt);
			continue;
		}
		if (!this->ss)
		{
			this->mutex->unlock(this->mutex);
			*packet = pkt;
			return SUCCESS;
		}
		src = pkt->get_source(pkt);
		if (!this->ss->is_from_server(this->ss, src))
		{
			/* not from the SS server, pass through unchanged */
			this->mutex->unlock(this->mutex);
			*packet = pkt;
			return SUCCESS;
		}
		if (this->ss->decrypt(this->ss, pkt->get_data(pkt), &src, &payload))
		{
			this->mutex->unlock(this->mutex);
			pkt->set_source(pkt, src);
			pkt->set_data(pkt, payload);
			DBG3(DBG_NET, "received Shadowsocks-relayed packet from %#H "
				 "(%zu bytes)", src, payload.len);
			*packet = pkt;
			return SUCCESS;
		}
		this->mutex->unlock(this->mutex);
		DBG2(DBG_NET, "discarding undecryptable Shadowsocks packet from %#H",
			 src);
		pkt->destroy(pkt);
	}
}

METHOD(socket_t, sender, status_t,
	private_socket_shadowsocks_socket_t *this, packet_t *packet)
{
	host_t *dst, *src;
	chunk_t sealed;

	update_config(this);
	this->mutex->lock(this->mutex);
	if (this->cfg_failed)
	{	/* Shadowsocks configured but unusable: drop, never leak plaintext */
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	if (!this->ss)
	{
		this->mutex->unlock(this->mutex);
		return this->inner->send(this->inner, packet);
	}
	dst = packet->get_destination(packet);
	src = this->ss->get_server(this->ss);
	src = host_create_from_sockaddr(src->get_sockaddr(src));
	if (!src)
	{
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	if (!this->ss->encrypt(this->ss, dst, packet->get_data(packet), &sealed))
	{
		DBG2(DBG_NET, "failed to Shadowsocks-encrypt packet to %#H", dst);
		this->mutex->unlock(this->mutex);
		src->destroy(src);
		return FAILED;
	}
	this->mutex->unlock(this->mutex);
	DBG3(DBG_NET, "relaying packet to %#H via Shadowsocks server (%zu bytes)",
		 dst, sealed.len);
	packet->set_destination(packet, src);
	packet->set_data(packet, sealed);
	return this->inner->send(this->inner, packet);
}

METHOD(socket_t, get_port, uint16_t,
	private_socket_shadowsocks_socket_t *this, bool nat_t)
{
	return this->inner->get_port(this->inner, nat_t);
}

METHOD(socket_t, supported_families, socket_family_t,
	private_socket_shadowsocks_socket_t *this)
{
	return this->inner->supported_families(this->inner);
}

METHOD(socket_t, destroy, void,
	private_socket_shadowsocks_socket_t *this)
{
	this->inner->destroy(this->inner);
	DESTROY_IF(this->ss);
	free(this->cfg_server);
	free(this->cfg_method);
	if (this->cfg_password)
	{
		memwipe(this->cfg_password, strlen(this->cfg_password));
		free(this->cfg_password);
	}
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
socket_shadowsocks_socket_t *socket_shadowsocks_socket_create()
{
	private_socket_shadowsocks_socket_t *this;
	socket_t *inner;

	inner = ss_inner_socket_create();
	if (!inner)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.socket = {
				.send = _sender,
				.receive = _receiver,
				.get_port = _get_port,
				.supported_families = _supported_families,
				.destroy = _destroy,
			},
		},
		.inner = inner,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);
	return &this->public;
}
