"""
LIEF MCP服务器 - 提供二进制文件分析能力
"""
from mcp.server.fastmcp import FastMCP
from tools import TOOLS

# 创建MCP服务器
mcp = FastMCP("LIEF Binary Analysis Server")

# 动态注册所有工具
for tool in TOOLS:
    mcp.tool()(tool)

if __name__ == "__main__":
    mcp.run()
