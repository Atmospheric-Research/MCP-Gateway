import os

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("echo")


@mcp.tool()
def echo(text: str) -> str:
    """Return the text unchanged."""
    return text


@mcp.tool()
def whoami() -> str:
    """Report the process id and the GREETING env var, to show per-session processes and server env."""
    return f"pid={os.getpid()} greeting={os.environ.get('GREETING', '')}"


if __name__ == "__main__":
    # MCP_PORT serves over streamable HTTP instead of stdio (used by the gateway's remote-server test).
    if port := os.environ.get("MCP_PORT"):
        mcp.run("streamable-http", host="127.0.0.1", port=int(port))
    else:
        mcp.run()
