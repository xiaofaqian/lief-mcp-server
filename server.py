"""
LIEF MCP服务器 - 提供二进制文件分析能力
"""
from mcp.server.fastmcp import FastMCP
from tools.get_binary_header import get_binary_header
from tools.query_exported_symbols import query_exported_symbols

# 创建MCP服务器
mcp = FastMCP("LIEF Binary Analysis Server")

# 注册工具
mcp.tool()(get_binary_header)
mcp.tool()(query_exported_symbols)

if __name__ == "__main__":
    mcp.run()
