"""
LIEF MCP服务器工具包

此模块包含所有用于二进制文件分析的MCP工具。
所有工具都遵循标准的MCP工具规范，提供统一的接口和异常处理。
"""

from .get_binary_header import get_binary_header
from .query_symbols import query_symbols
from .add_macho_function_symbol import add_macho_function_symbol
from .remove_macho_symbol import remove_macho_symbol
from .query_macho_method_references import query_macho_method_references
from .disassemble_macho_at_address import disassemble_macho_at_address
from .assemble_to_bytes import assemble_to_bytes

# 导出所有工具函数
__all__ = [
    "get_binary_header",
    "query_symbols",
    "add_macho_function_symbol",
    "remove_macho_symbol",
    "query_macho_method_references",
    "disassemble_macho_at_address",
    "assemble_to_bytes"
]

# 工具列表，便于动态注册
TOOLS = [
    get_binary_header,
    query_symbols,
    add_macho_function_symbol,
    remove_macho_symbol,
    query_macho_method_references,
    disassemble_macho_at_address,
    assemble_to_bytes
]
