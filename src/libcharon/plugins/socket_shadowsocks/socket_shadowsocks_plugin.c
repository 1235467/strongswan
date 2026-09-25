/*
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

#include "socket_shadowsocks_plugin.h"

#include "socket_shadowsocks_socket.h"

#include <daemon.h>

typedef struct private_socket_shadowsocks_plugin_t
	private_socket_shadowsocks_plugin_t;

/**
 * Private data of the plugin.
 */
struct private_socket_shadowsocks_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	socket_shadowsocks_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_socket_shadowsocks_plugin_t *this)
{
	return "socket-shadowsocks";
}

METHOD(plugin_t, destroy, void,
	private_socket_shadowsocks_plugin_t *this)
{
	free(this);
}

METHOD(plugin_t, get_features, int,
	private_socket_shadowsocks_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(socket_register, socket_shadowsocks_socket_create),
			PLUGIN_PROVIDE(CUSTOM, "socket"),
				PLUGIN_SDEPEND(CUSTOM, "kernel-ipsec"),
	};
	*features = f;
	return countof(f);
}

/*
 * see header file
 */
PLUGIN_DEFINE(socket_shadowsocks)
{
	private_socket_shadowsocks_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
