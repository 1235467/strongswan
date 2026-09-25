/*
 * Compiles the default socket implementation into this plugin with a renamed
 * public symbol (ss_inner_socket_create instead of socket_default_socket_
 * create).  This allows the socket-shadowsocks plugin to wrap the real
 * socket code without modifying any upstream file and without symbol clashes
 * even if the socket-default plugin is enabled at the same time.
 *
 * Copyright (C) 2026 strongSwan contributors
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version. See <http://www.gnu.org/licenses/>.
 */

#define socket_default_socket_create ss_inner_socket_create
#include "../socket_default/socket_default_socket.c"
