# FRP tunnels from gntl

gntl runs `frpc` locally and registers proxies on a remote `frps`. How the
proxy must be declared depends on whether that server terminates TLS at an edge
proxy before frps sees the request.

## silverqueen.pro is edge-terminated

`silverqueen.pro` fronts frps with Caddy: Caddy owns the certificate for
`*.silverqueen.pro`, terminates TLS, and forwards plaintext to the frps **HTTP** vhost
(`:7080`). So a proxy published there must be `type = "http"`.

Declaring `type = "https"` puts the proxy on the frps HTTPS vhost (`:7443`),
which the edge never routes to. The tunnel then shows `online` everywhere —
the frps dashboard, `/admin/hosting/tunnels`, the gntl instance list — while
every browser request returns frps' "Tunnel Not Found" 404 page. Nothing in the
status surface reveals the mismatch, which makes it an expensive bug to chase.

A TLS-only local app is still tunnelled without downgrading the local hop:
`render_frpc_config()` emits frpc's `http2https` plugin, so frps hands frpc
plaintext and frpc re-wraps it in TLS for the local service.

```toml
[[proxies]]
name = "btc-https"
type = "http"
subdomain = "btc"
[proxies.plugin]
type = "http2https"
localAddr = "127.0.0.1:2026"
hostHeaderRewrite = "127.0.0.1"
```

## Existing tunnels migrate themselves

A tunnel created before this rule existed still has `type = "https"` in its
`.toml`. `_migrate_edge_tls_proxies()` rewrites it on load — only when
`serverAddr` is edge-terminated — converting it to `http` and moving the local
endpoint into an `http2https` plugin. Upgrading and restarting is therefore
enough; there is no need to delete and recreate the tunnel.

## Other frps servers are left alone

The rule above is scoped by hostname, not applied globally:

- `FRP_EDGE_TLS_HOSTS` (env `GNTL_FRP_EDGE_TLS_HOSTS`, default `silverqueen.pro`)
  lists the servers known to be edge-terminated. Matching is exact or by parent
  domain.
- For any other `serverAddr`, gntl keeps using the protocol the local app
  actually speaks, exactly as before.

This matters because more than one frps can be in play. On the silverqueen.pro host
there is a second, separately configured frps on port `7700` with no vhost
ports, serving its own purpose. It is not part of the `*.silverqueen.pro` path and
must not be reconfigured to match it. See `docs/frp.md` in the silverqueen.pro repo
for the full comparison of the two servers.

## Binding with an account key

A key generated at `silverqueen.pro/account/keys` is the only credential a machine
needs. It names the subdomain, identifies the owner, and carries its own
expiry, so there is no admin approval step.

```
paste key ──► POST /api/tunnel/bind (gntl)
                 │
                 ├─► POST https://silverqueen.pro/api/tunnel/bind      (authorise)
                 │      └── returns serverAddr, port, frps token, proxy_type
                 ├─► render frpc config + start the tunnel
                 └─► POST https://silverqueen.pro/api/tunnel/bind again (confirm)
                        └── server reads ginto_key off the live proxy and
                            enables the strict binding
```

The two-phase call exists because the server refuses to take the client's word
for the meta: it checks the frps dashboard for the running proxy and only
enables the operator-key requirement when the published key actually matches.
Enabling it for a proxy that does not publish the meta would make
`verifyTunnel()` refuse certificates for that subdomain — a bind that caused an
outage.

Bound keys live in `configs/tunnel_keys.json` (mode `0600`, since they are live
credentials). Rendered `.toml` files are `0600` too — they contain the frps
token.

### Binding without a browser

`/api/tunnel/bind` sits behind the admin session, so on a headless machine use
the CLI instead. It does the same work directly against the config directory -
the same trust boundary the web session protects:

```bash
./run.sh bind gtnl-... 2026          # key, then the local port
./run.sh bind gtnl-... --no-restart  # write the config, start it later
```

It accepts either a bare key or the whole "Link format" line from the keys
page. When the manager runs under systemd it restarts the service so the new
tunnel is adopted, rather than starting a second frpc behind its back.

### One tunnel per subdomain

frps serves exactly one proxy per subdomain. A second instance for the same
name never works - it loses the registration race and sits offline retrying -
so both creation paths check `_find_instance_for_subdomain()` first:

- binding a key **adopts** an instance that already serves that subdomain,
  rewriting its config instead of adding a rival
- the manual create form refuses with a 409 naming the instance that holds it

The check is per `(serverAddr, subdomain)`, so the same name on a different
frps is a separate claim and is not blocked.

## Surviving a reboot

This is the default. `./run.sh` installs a systemd unit, starts it, and then
follows the log — Ctrl+C leaves the server running.

```bash
./run.sh              # start as a service and follow the log
./run.sh stop         # stop now, and stay stopped across reboots
./run.sh status       # service status
./run.sh foreground   # this terminal only, no service
```

The manager auto-starts every enabled instance when it comes up, so keeping the
manager alive is all that persistence requires — there is no per-tunnel unit to
manage.

The unit carries `GNTL_TLS_CERT`/`GNTL_TLS_KEY` explicitly. Without them the
service would come up serving plain HTTP on 2027 only, leaving 2026 dead — the
LAN address *and* the tunnel origin.

Hosts without systemd, or without root, fall back to the foreground automatically.

## Where this lives in the code

| Concern | Location |
|---|---|
| Proxy type + local TLS decision | `_frp_exposure_plan()` in `backend/src/gntl/main.py` |
| Local protocol probe | `_detect_local_app_protocol()` |
| Config rendering (create time) | `render_frpc_config()` in `main.py` |
| Config rewriting (every load) | `FrpcManager._render_frpc_config()` in `tunnel_manager.py` |
| Key bind flow | `bind_tunnel_key()` / `_ginto_bind_call()` in `main.py` |
| Key storage | `_load_tunnel_keys()` / `_save_tunnel_keys()` |
| Boot service | `install_manager_service()` in `run.sh` |

Both renderers must agree. `_normalize_config_shape()` rewrites every `.toml`
on startup, so a field the manager's renderer does not know about is silently
dropped on the next restart — that is why it carries the `[proxies.plugin]`
block explicitly, and why it omits `localIP`/`localPort` when a plugin is
present.

## Checking a tunnel

```bash
# does frps list the subdomain on the HTTP vhost? (this is what makes it reachable)
curl -s -u "admin:$FRP_DASHBOARD_PWD" http://127.0.0.1:7500/api/proxy/http

# local frpc log
tail -f /tmp/frpc-tunnel.log
```
