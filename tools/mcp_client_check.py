"""Talk to `pz mcp` with the official MCP client library, the way a coding agent's host would.

    pip install mcp
    python tools/mcp_client_check.py "$(command -v pz)" examples/vibe-clinic

Exits non-zero if the handshake, the tool list or a tool call does not behave.
"""
import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(command=sys.argv[1], args=["mcp"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            print("server:", init.server_info.name, init.server_info.version, "protocol", init.protocol_version)
            tools = await s.list_tools()
            print("tools:", [t.name for t in tools.tools])
            res = await s.call_tool("pz_check", {"path": sys.argv[2]})
            d = json.loads(res.content[0].text)
            print("pz_check:", d["files_scanned"], "files, worst", d["worst"], "isError", getattr(res, "is_error", getattr(res, "isError", None)))
            res = await s.call_tool("pz_explain", {"control": "GATE-3"})
            print("pz_explain:", json.loads(res.content[0].text)["in_plain_words"])
            res = await s.call_tool("pz_explain", {"control": "NOPE"})
            print("bad control isError:", getattr(res, "is_error", getattr(res, "isError", None)))
            await s.send_ping()
            print("ping ok")
            assert len(tools.tools) == 6 and d["worst"] == "critical"

asyncio.run(asyncio.wait_for(main(), 60))
