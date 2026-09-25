AM_CPPFLAGS = \
	-I${linux_headers} \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-socket-shadowsocks.la
else
plugin_LTLIBRARIES = libstrongswan-socket-shadowsocks.la
endif

libstrongswan_socket_shadowsocks_la_SOURCES = \
	socket_shadowsocks_plugin.h socket_shadowsocks_plugin.c \
	socket_shadowsocks_socket.h socket_shadowsocks_socket.c \
	socket_shadowsocks_ss.h socket_shadowsocks_ss.c \
	socket_shadowsocks_inner.c

libstrongswan_socket_shadowsocks_la_LDFLAGS = -module -avoid-version
