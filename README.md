# NordStellar MCP

Connect any MCP-compatible AI assistant to NordStellar so you can query your platform data directly from chat.

## What you get

- Use natural language to ask about NordStellar data
- No need to switch to the NordStellar UI or write GraphQL by hand
- Secure login via your NordStellar account

## Setup

### 1. Add to your MCP client

Add the NordStellar MCP server to your AI assistant’s MCP configuration (e.g. `mcp.json` or the equivalent in your client):

```json
{
  "nordstellar-graphql": {
    "command": "uvx",
    "args": [
      "--from", "git+https://github.com/sirakav/ns-mcp-proxy",
      "nordstellar-remote-mcp-proxy",
      "http://your-server:8080/mcp"
    ]
  }
}
```

Replace `http://your-server:8080/mcp` with the MCP endpoint URL provided by your NordStellar administrator.

### 2. First-time login

When you first use NordStellar, a browser window will open. Sign in with your NordStellar credentials. After that, you’re set—the connection stays authenticated until you sign out or the session expires.

### 3. Start using it

Ask your AI assistant things like “What projects do I have?” or “Show me recent activity” and it will use your NordStellar data to answer.

## Requirements

- [uv](https://docs.astral.sh/uv/) installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Python 3.10 or newer (uv handles this automatically)

## Need help?

Contact your NordStellar administrator for the correct MCP endpoint URL and any access questions.
