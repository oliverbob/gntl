# FRP tunnels from gntl

gntl runs `frpc` locally and registers proxies on a remote `frps`. How the
proxy must be declared depends on whether that server terminates TLS at an edge
proxy before frps sees the request.

## ginto.ai is edge-terminated

`ginto.ai` fronts frps with Caddy: Caddy owns the certificate for
`*.ginto.ai`, terminates TLS, and forwards plaintext to the frps **HTTP** vhost
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

## Other frps servers are left alone

The rule above is scoped by hostname, not applied globally:

- `FRP_EDGE_TLS_HOSTS` (env `GNTL_FRP_EDGE_TLS_HOSTS`, default `ginto.ai`)
  lists the servers known to be edge-terminated. Matching is exact or by parent
  domain.
- For any other `serverAddr`, gntl keeps using the protocol the local app
  actually speaks, exactly as before.

This matters because more than one frps can be in play. On the ginto.ai host
there is a second, separately configured frps on port `7700` with no vhost
ports, serving its own purpose. It is not part of the `*.ginto.ai` path and
must not be reconfigured to match it. See `docs/frp.md` in the ginto.ai repo
for the full comparison of the two servers.

## Where this lives in the code

| Concern | Location |
|---|---|
| Proxy type + local TLS decision | `_frp_exposure_plan()` in `backend/src/gntl/main.py` |
| Local protocol probe | `_detect_local_app_protocol()` |
| Config rendering (create time) | `render_frpc_config()` in `main.py` |
| Config rewriting (every load) | `FrpcManager._render_frpc_config()` in `tunnel_manager.py` |

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
