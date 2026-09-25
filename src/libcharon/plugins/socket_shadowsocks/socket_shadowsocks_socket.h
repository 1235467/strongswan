/*
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

/**
 * @defgroup socket_shadowsocks_socket socket_shadowsocks_socket
 * @{ @ingroup socket_shadowsocks
 */

#ifndef SOCKET_SHADOWSOCKS_SOCKET_H_
#define SOCKET_SHADOWSOCKS_SOCKET_H_

typedef struct socket_shadowsocks_socket_t socket_shadowsocks_socket_t;

#include <network/socket.h>

/**
 * Socket implementation relaying all IKE/ESP UDP traffic through a
 * Shadowsocks server (UDP relay).
 */
struct socket_shadowsocks_socket_t {

	/**
	 * Implements socket_t interface.
	 */
	socket_t socket;
};

/**
 * Create the socket.
 *
 * @return		socket_t object, NULL on failure
 */
socket_shadowsocks_socket_t *socket_shadowsocks_socket_create();

#endif /** SOCKET_SHADOWSOCKS_SOCKET_H_ @}*/
