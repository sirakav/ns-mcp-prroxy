# nordstellar-remote-mcp-proxy

A lightweight Python proxy that handles NordStellar authentication and forwards MCP tool calls to a remote Go MCP server over StreamableHTTP.

## How it works

1. On first run, opens a browser window for NordStellar login (cookie-based OAuth flow)
2. Extracts the JWT from the `AccessToken` cookie
3. Proxies all MCP requests to the remote server using the JWT as a `Bearer` token
4. Re-authenticates transparently when the token expires

The remote Go server (`cmd/remote-hack`) accepts the Bearer token and converts it back into an `AccessToken` cookie for the NordStellar GraphQL backend.

## Usage

### Cursor `mcp.json` (recommended — no local clone needed)

```json
{
  "nordstellar-graphql": {
    "command": "uvx",
    "args": [
      "--from", "git+https://github.com/sirakav/ns-mcp-prroxy",
      "nordstellar-remote-mcp-proxy",
      "http://my-server:8080/mcp"
    ]
  }
}
```

`uvx` installs and caches the package from GitHub on first run.

### Local run

```bash
uv run nordstellar_remote_mcp_proxy.py http://my-server:8080/mcp
```

Or after installing:

```bash
uvx --from . nordstellar-remote-mcp-proxy http://my-server:8080/mcp
```

## Requirements

- Python ≥ 3.10
- [uv](https://docs.astral.sh/uv/) installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
