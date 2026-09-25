/*
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

/**
 * @defgroup socket_shadowsocks socket_shadowsocks
 * @ingroup cplugins
 *
 * @defgroup socket_shadowsocks_plugin socket_shadowsocks_plugin
 * @{ @ingroup socket_shadowsocks
 */

#ifndef SOCKET_SHADOWSOCKS_PLUGIN_H_
#define SOCKET_SHADOWSOCKS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct socket_shadowsocks_plugin_t socket_shadowsocks_plugin_t;

/**
 * Socket plugin relaying IKE/ESP traffic via a Shadowsocks server.
 *
 * Mutually exclusive with socket-default (both provide a socket).
 */
struct socket_shadowsocks_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** SOCKET_SHADOWSOCKS_PLUGIN_H_ @}*/
