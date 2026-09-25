# IKEv2 over Shadowsocks (UDP relay)

Goal: route IKEv2/IPsec traffic (UDP 500/4500) through a Shadowsocks server via
its UDP relay capability, so the IKE handshake and ESP-in-UDP traffic are
indistinguishable from SS traffic and don't hit censorship/QoS on the wire.

## Background

On Linux this is done with sing-box: a TUN inbound intercepts
charon-systemd's UDP packets and a `shadowsocks` outbound relays them
(`process_name`/dst-IP rules → ss outbound → SS server → real VPN server).

On Android this is impossible without root: only one `VpnService` may run per
profile and VPN apps cannot be chained (a protected socket bypasses *all* VPNs).

However, the strongSwan Android app is perfectly suited to do the SS
encapsulation itself:

- ESP on Android is always UDP-encapsulated: `kernel_android_ipsec` requires
  `KERNEL_REQUIRE_UDP_ENCAPSULATION` and the app sets `force_encap = TRUE`, so
  **all** IKE/IPsec traffic is UDP datagrams on ports 500/4500.
- Every IKE and ESP datagram passes through one choke point: the `socket_t`
  interface (`charon->socket->send()/receive()`), implemented by the
  socket-default plugin.
- `VpnService.protect()` is already wired (`bypass_socket`), so the SS-bound
  UDP packets go over the physical network and are never sucked into our own
  TUN.

## Design

New charon plugin **`socket-shadowsocks`**: a pure decorator over
socket-default. No upstream file is modified; the whole feature lives in
`src/libcharon/plugins/socket_shadowsocks/` plus small hook points.

### Packet flow

```
send:    packet(dst=vpn:500/4500, data=IKE|ESP)
         → build SOCKS5 addr header for dst + payload
         → AEAD seal (fresh per-packet salt): salt || AEAD(subkey, 0^12, addr||data) || tag
         → set_destination(packet, ss_server), set_data(packet, sealed)
         → inner socket_default send() → sendmsg to ss_server:port

receive: packet(src=ss_server:port, data=sealed)
         → verify src == configured ss_server (else passthrough)
         → open AEAD, parse SOCKS5 addr header → set_source(packet, real_vpn:port)
         → charon sees a packet "from" the real VPN server
```

charon/IKE_SA still see the real VPN server address: identity checks, NAT-D,
MOBIKE and the TUN datapath are all unaffected.

### Crypto (classic AEAD methods)

Reference implementation: shadowsocks-c (formerly shadowsocks-libev),
`src/aead.c` UDP path.

- master key = EVP_BytesToKey(MD5, password, key_len)
- per-packet: salt (key_len random bytes), subkey = HKDF-SHA1(master, salt,
  "ss-subkey"), nonce = 12 zero bytes
- wire format: `salt || AEAD(subkey, nonce, [ATYP|addr|port] || payload) || tag(16)`

All primitives map onto libstrongswan (openssl plugin, already in the Android
build): `HASH_MD5`, `PRF_HMAC_SHA1` (HKDF implemented manually on prf_t),
`RNG_STRONG`, `aead_t` (ENCR_AES_GCM_ICV16 / ENCR_CHACHA20_POLY1305; key =
subkey || 4B zero salt, iv = 8 zero bytes → 12B zero nonce).

Supported methods: `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`,
`chacha20-ietf-poly1305`.

### 2022-blake3-* (TODO, not yet implemented)

Method names are recognized in the cipher table; configuring one logs an error
("not yet implemented") and fails closed (packets dropped, never sent in the
clear).

Implementation notes for later: port client-side session logic from
shadowsocks-c `src/aead2022_udp.c` (random session_id + monotonic packet_id,
BLAKE3 `derive_key` subkeys, base64 PSK instead of password). Vendor the 3
portable BLAKE3 C files (`src/blake3/`, CC0/Apache-2.0) — neither OpenSSL nor
libstrongswan has BLAKE3. Check whether the server requires EIH (multi-user
identity headers).

### Fail-closed behavior

If `server` is configured but the context can't be initialized (bad method,
missing password, 2022-*), send() fails → IKE just times out. Packets are
never sent unencrypted when SS is configured.

### Configuration (never hardcoded)

strongswan.conf style:

```
charon.plugins.socket-shadowsocks {
    server = 114.80.150.220
    port = 53622
    method = aes-128-gcm
    password = ...
}
```

App flow (per VPN profile, all user-configurable):

```
VpnProfileDetailActivity  (new "Shadowsocks relay" section in advanced settings)
  → VpnProfile (mSsServer/mSsPort/mSsMethod/mSsPassword)
  → DB: 4 new columns, DATABASE_VERSION 19 → 20 (auto ALTER TABLE via DbColumn.Since)
  → CharonVpnService: connection.ss_server/_port/_method/_password
  → initiate() → charonservice.c copies to charon.plugins.socket-shadowsocks.*
  → socket reads config lazily on first packet (socket is instantiated at
    initializeCharon(), profile settings arrive at initiate() — lazy read is
    required; each connect re-inits charon anyway)
```

## Files

### New (C, `src/libcharon/plugins/socket_shadowsocks/`)

- `socket_shadowsocks_plugin.{c,h}` — plugin boilerplate,
  PROVIDE(CUSTOM,"socket"), SDEPEND kernel-ipsec
- `socket_shadowsocks_socket.{c,h}` — socket_t decorator: lazy config, wraps
  inner socket, wraps/unwraps packets
- `socket_shadowsocks_ss.{c,h}` — SS codec: method table, key derivation,
  SOCKS5 addr codec, seal/open
- `socket_shadowsocks_inner.c` — compiles socket_default_socket.c with a
  renamed public symbol:
  `#define socket_default_socket_create ss_inner_socket_create` +
  `#include "../socket_default/socket_default_socket.c"` (zero upstream edits,
  no symbol clash even if socket-default is also enabled)
- `Makefile.am`

### Modified (build)

- `configure.ac` — `ARG_ENABL_SET(socket-shadowsocks)`, `ADD_PLUGIN(...)`,
  `AM_CONDITIONAL(USE_SOCKET_SHADOWSOCKS)`, AC_CONFIG_FILES entry
- `src/libcharon/Makefile.am` — SUBDIRS + LIBADD under `if USE_SOCKET_SHADOWSOCKS`
- `src/frontends/android/app/src/main/jni/Android.mk` —
  `socket-default` → `socket-shadowsocks` in `strongswan_CHARON_PLUGINS`
- `src/libcharon/Android.mk` — `add_plugin(socket-shadowsocks)` + explicit
  `plugins/socket_default/socket_default_socket.c` when the plugin is enabled
  (its plugin glob no longer includes it once socket-default is dropped)

  NOTE on Android.mk: the inner.c trick can't be used for ndk-build since
  add_plugin only globs `socket_shadowsocks*.c`; instead we compile
  socket_default_socket.c directly and declare `ss_inner_socket_create`
  ourselves… — resolved by giving the inner wrapper its own translation unit
  everywhere (the #include trick works with ndk-build too, the glob picks up
  socket_shadowsocks_inner.c and it includes the socket_default .c).

### Modified (C)

- `src/frontends/android/app/src/main/jni/libandroidbridge/charonservice.c`
  — in `initiate()`, copy `connection.ss_*` into
  `charon.plugins.socket-shadowsocks.*`

### Modified (Java/Android)

- `data/VpnProfileDataSource.java` — 4 KEY_SS_* constants
- `data/DatabaseHelper.java` — 4 columns since=20, DATABASE_VERSION=20
- `data/VpnProfile.java` — fields + accessors
- `data/VpnProfileSqlDataSource.java` — cursor/ContentValues mapping
- `logic/CharonVpnService.java` — 4 writer.setValue() calls
- `ui/VpnProfileDetailActivity.java` — findViewById, load/save/verify/readonly
- `res/layout/profile_detail_view.xml` — Shadowsocks section (advanced)
- `res/values/arrays.xml` — ss_methods list
- `res/values*/strings.xml` — labels/hints (en + zh-rCN)

### Not changed

socket-default sources, libipsec, TUN/protect handling, MOBIKE, auth logic.

## Status (2026-09)

Implemented: codec + decorator + plugin + autotools/Android build wiring +
profile DB/UI/charonservice plumbing.  Host build verified (autotools,
-Werror clean).

Codec verified against a real sing-box server (local loopback, UDP echo
target): aes-128-gcm, aes-192-gcm, aes-256-gcm, chacha20-ietf-poly1305 all
round-trip correctly in both directions, incl. IPv6 targets; wrong password
fails closed.  2022-blake3-* recognized but not implemented (fails closed).

## Verification (user-side, after implementation)

1. Configure SS relay on a profile; connect — IKE_SA should establish via the
   SS server (server log should show peer = SS server IP).
2. `logcat`/`charon` log: look for `socket-shadowsocks` init line and absence
   of errors.
3. SS disabled profile → behaves exactly like upstream.
4. 2022-blake3-* selected → clean "not implemented" error, no plaintext leak.

## Notes / caveats

- SS server must have UDP relay enabled (sing-box `shadowsocks` outbound does).
- ~+40-50B overhead per datagram (salt+addr+tag). TUN MTU 1400 is fine; lower
  to ~1300 if path MTU is small.
- VPN server sees SS server's IP as client address.
- IKE retransmit/DPD timers unchanged; NAT-T keepalives keep the SS NAT
  binding warm.
- SS server address family should match the IKE transport family (the inner
  socket picks IPv4/IPv6 socket by destination family and binds the packet's
  source address to it).
- Domain-name targets in SS replies are not parsed (servers echo literal IPs).
- License: ported SS logic follows shadowsocks-c (GPLv3); strongSwan is
  GPLv2-or-later → combined work GPLv3. BLAKE3 files CC0/Apache-2.0.
