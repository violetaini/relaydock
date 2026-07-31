# Managed protocol connectivity acceptance

`scripts/protocol_connectivity_acceptance.py` is a destructive-free, local
end-to-end acceptance runner for the protocols exposed by the managed-node UI.
It does not call Arcway APIs, edit Xray configuration, open firewall ports, or
write outside a mode-0700 temporary directory.

## Requirements

- Linux loopback networking (`127.0.0.0/8`)
- Python 3.10 or newer
- Arcway's Xray `26.3.27` binary
- `openssl`
- `curl` for connectivity mode

The exact Xray version is enforced before credentials or configuration files
are generated. Override it only when intentionally accepting a new pinned
core version.

## Commands

List every case without requiring Xray:

```sh
python3 scripts/protocol_connectivity_acceptance.py --list
```

Validate every generated Xray configuration:

```sh
ARCWAY_ACCEPTANCE_XRAY_BIN=/path/to/xray \
  python3 scripts/protocol_connectivity_acceptance.py --validate-only
```

Run the complete connectivity matrix:

```sh
ARCWAY_ACCEPTANCE_XRAY_BIN=/path/to/xray \
  python3 scripts/protocol_connectivity_acceptance.py
```

Run selected cases:

```sh
ARCWAY_ACCEPTANCE_XRAY_BIN=/path/to/xray \
  python3 scripts/protocol_connectivity_acceptance.py \
  --case hysteria2 --case wireguard --case anydoor --fail-fast
```

The successful full run ends with `PASSED: 21 of 21 case(s)`. There are 21
executions for 20 UI presets because the Shadowsocks preset is exercised once
with AES-128-GCM and once with 2022 BLAKE3 AES-128-GCM multi-user credentials.

## Current result

On 2026-07-26, the full matrix passed against the locally built Arcway Xray
`26.3.27` source at commit `3cd8c5f`: config validation passed 21/21 and real
connectivity passed 21/21. This proves the protocol engine and generated
configuration shapes. Panel API creation and persistence are covered by the
separate guarded post-deployment runner described below.

## Coverage

| UI preset | Executed case | End-to-end proof |
| --- | --- | --- |
| VLESS Reality | `vless-reality` | SOCKS client, Reality server, HTTP exit |
| VLESS TLS | `vless-tls` | SOCKS client, pinned TLS server, HTTP exit |
| VLESS gRPC TLS | `vless-grpc-tls` | gRPC over pinned TLS, HTTP exit |
| VLESS WS | `vless-ws` | WebSocket, HTTP exit |
| VLESS WSS | `vless-wss` | WSS through temporary TLS terminator, HTTP exit |
| VMess TCP | `vmess` | TCP, HTTP exit |
| VMess TLS | `vmess-tls` | pinned TLS, HTTP exit |
| VMess gRPC TLS | `vmess-grpc-tls` | gRPC over pinned TLS, HTTP exit |
| VMess WS | `vmess-ws` | WebSocket, HTTP exit |
| VMess WSS | `vmess-wss` | WSS through temporary TLS terminator, HTTP exit |
| Trojan TLS | `trojan` | pinned TLS, HTTP exit |
| Trojan Reality | `trojan-reality` | Reality, HTTP exit |
| Trojan gRPC TLS | `trojan-grpc-tls` | gRPC over pinned TLS, HTTP exit |
| Trojan WSS | `trojan-wss` | WSS through temporary TLS terminator, HTTP exit |
| Shadowsocks | `shadowsocks-classic` | AES-128-GCM, HTTP exit |
| Shadowsocks | `shadowsocks-2022` | 2022 multi-user credentials, HTTP exit |
| Hysteria2 | `hysteria2` | Xray 26.3.27 QUIC/UDP with `clients`, `h3`, HTTP exit |
| SOCKS5 | `socks5` | authenticated server, HTTP exit |
| HTTP proxy | `http` | authenticated server, HTTP exit |
| WireGuard | `wireguard` | Xray WireGuard inbound and userspace Xray client, HTTP exit |
| AnyDoor | `anydoor` | A-B-C same-port chain, TCP HTTP and UDP nonce echo |

For the HTTP exit checks, the origin must see `127.0.0.2`. This proves the
request reached the server-side Xray process; a client-side direct connection
cannot accidentally pass.

## Environment substitutions

Production-managed certificates are replaced with a one-day temporary
self-signed certificate. Clients validate its SHA-256 pin and name; the runner
never enables insecure TLS verification. WSS uses a temporary TLS forwarder to
represent the external Nginx termination used by managed WSS nodes. Reality
uses a temporary TLS camouflage origin.

WireGuard uses the exact managed inbound shape. Its ephemeral Xray client sets
`noKernelTun: true`, and Xray 26.3.27 always uses gVisor for WireGuard inbounds,
so the check requires no host routes, kernel interface, or network namespace.
The client requests the reserved benchmark address `198.18.0.1`; after it
crosses WireGuard, the server's temporary Freedom outbound redirects it to the
loopback origin. This avoids gVisor treating a `127.0.0.1` destination as the
client's own virtual loopback while keeping every real listener on loopback.

AnyDoor binds A, B, and C to `127.0.0.10`, `127.0.0.11`, and `127.0.0.12` on
one randomly reserved numeric port. Every hop enables `tcp,udp`. The final hop
targets an origin that listens on TCP and UDP on its own shared port.

## Security and cleanup

Credentials and X25519 keys are generated in memory. Temporary configuration,
certificate, and key files use mode 0600; their directory uses mode 0700.
Xray output is suppressed during connectivity checks, validation errors are
redacted, and the temporary directory and child processes are removed on
success, failure, or interruption. The runner never prints generated secrets.

## Panel-level release acceptance

The local matrix proves the exact generated protocol shapes can carry traffic,
but it does not prove the UI/API persistence path. After a deployment, complete
release acceptance through the panel on disposable test nodes:

1. Create the 18 standard managed-node presets through the same API used by the
   UI, using random allowed-range ports. Execute Shadowsocks twice for classic
   AEAD and 2022 multi-user, for 19 standard executions in total.
2. Read each node back and compare its persisted inbound and client options to
   the submitted preset. Record only case and node IDs, never credentials.
3. Connect with the emitted client configuration and require the same HTTP exit
   assertion. Require a real Hysteria2 QUIC connection and a WireGuard
   handshake, not only config validation.
4. Create WireGuard through its dedicated API, require the encrypted client
   configuration to appear as a normal node and subscription/share item, then
   require a real handshake using the recovered client configuration.
5. Build AnyDoor A-B-C with the same numeric port (use 2033 when explicitly
   reserved for staging), then require both its TCP and UDP checks.
6. Delete only the disposable node IDs created by this run and confirm their
   listeners are gone.

Imported Mihomo-only protocols such as TUIC and AnyTLS are outside the
managed Xray matrix. Test them separately with the deployed Mihomo version:
configuration validation, an HTTP exit request, and UDP where that protocol
promises UDP support.

### Guarded panel runner

`scripts/panel_protocol_connectivity_acceptance.py` automates the standard
managed protocols through the real panel API. It creates a uniquely prefixed
inbound, verifies the returned database node and Agent inbound readback,
converts the persisted Clash node to an Xray 26.3.27 client, and sends a real
HTTP request through that client. WireGuard and AnyDoor remain a separate phase
because WireGuard has a dedicated peer-creation request and AnyDoor spans
multiple servers. A successfully created WireGuard entry otherwise follows the
same node, package, subscription, share and deletion lifecycle as other nodes.

Without `--execute`, the command is a dry run and sends no API request. The
admin session token is read only from an environment variable, never from a
command-line argument:

```sh
export ARCWAY_ACCEPTANCE_TOKEN='session token from the panel'
export ARCWAY_ACCEPTANCE_XRAY_BIN=/path/to/xray
python3 scripts/panel_protocol_connectivity_acceptance.py \
  --base-url https://panel.example \
  --server-id 1 \
  --certificate-id 12 \
  --tls-domain test.example.com \
  --wss-domain test.example.com
```

After reviewing the dry-run summary, append `--execute`. Cleanup is enabled by
default and deletes only inbound tags under this run's random
`accept-<run-id>-` prefix. `--keep` leaves those disposable resources for
manual inspection. Existing unprefixed resources are never eligible.

For a strong exit assertion, keep the default IP echo probe and pass the
expected public egress address with `--expected-exit-ip`. Select a smaller set
with repeated `--case` options. TLS cases require a valid certificate belonging
to the selected server. WSS also requires the server's managed domain and Nginx
certificate context. The runner does not upload certificates, change server
domains, or disable panel TLS verification. For a disposable self-signed test
certificate, `--skip-cert-verify` explicitly relaxes only the generated client;
it never writes `allowInsecure` into the server inbound.

### Guarded WireGuard and AnyDoor runner

`scripts/panel_special_connectivity_acceptance.py` covers the two resources
that do not use the standard managed-node lifecycle. It is also a dry run
unless `--execute` is supplied, and cleanup cannot be disabled.

- WireGuard is created through
  `/api/admin/managed-inbound-resources/wireguard`. The authenticated request
  carries server `inbound` and client `client` objects separately, so the
  client private key is encrypted in panel storage and is never forwarded in
  the Agent inbound request. The runner requires the response to include the
  compatibility `resource`, normal `node`, and recoverable `client_config`;
  it then verifies the node through `/api/admin/nodes`, requires its
  `wireguard://` subscription/share representation, and proves TCP HTTP plus
  inner UDP DNS connectivity. Cleanup uses the ordinary node deletion API and
  confirms that the node, compatibility resource, and remote inbound all
  disappear. The resource API is used only to clean a half-completed create.
- AnyDoor is created through `/api/admin/tunnel-chains`. Every managed hop and
  the final echo target use one explicit numeric port. The runner requires both
  a TCP nonce echo and a UDP nonce echo, removes hop tags in reverse order, and
  confirms every tag is absent.

The WireGuard create body uses this contract (placeholder values shown):

```json
{
  "action": "add",
  "display_name": "Acceptance WireGuard",
  "inbound": {
    "tag": "accept-<run-id>-wireguard",
    "protocol": "wireguard",
    "port": 51920,
    "settings": {
      "secretKey": "<server-private-key>",
      "address": ["10.200.1.1/32"],
      "mtu": 1420,
      "peers": [
        {
          "publicKey": "<client-public-key>",
          "allowedIPs": ["10.200.1.2/32"],
          "keepAlive": 25
        }
      ]
    }
  },
  "client": {
    "private_key": "<client-private-key>",
    "public_key": "<client-public-key>",
    "address": ["10.200.1.2/32"],
    "dns": ["1.1.1.1"],
    "mtu": 1420,
    "keep_alive": 25,
    "server_public_key": "<server-public-key>",
    "allowed_ips": ["0.0.0.0/0"]
  }
}
```

Only `inbound` is sent to the Agent. The server derives the normal Clash node
and downloadable `.conf` from `client`, encrypts the sensitive node fields at
rest, and decrypts them only for an authorized node, subscription or share
response.

Run the AnyDoor phase on the third host that will act as C, or point it at an
equivalent external TCP/UDP echo process. `--serve-echo` opens a temporary,
non-amplifying echo listener locally; `--target-host` must be the address by
which the last managed server can reach that host. The host and cloud firewall
must already allow the selected TCP and UDP port. The runner never changes a
firewall itself.

```sh
export ARCWAY_ACCEPTANCE_TOKEN='session token from the panel'
export ARCWAY_ACCEPTANCE_XRAY_BIN=/path/to/xray
python3 scripts/panel_special_connectivity_acceptance.py \
  --base-url https://panel.example \
  --wireguard-server-id 1 \
  --chain-server-id 1 \
  --chain-server-id 2 \
  --anydoor-port 2033 \
  --target-host 192.0.2.10 \
  --serve-echo \
  --expected-exit-ip 192.0.2.20
```

Review the dry-run summary, then append `--execute`. For a disposable random
same-port check instead of port 2033, omit `--anydoor-port` while using
`--serve-echo`; the local echo listener selects a free port and the chain API
requires that exact port to be free on every managed hop.
