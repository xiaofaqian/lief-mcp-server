"""
LIEF MCP服务器工具包

此模块包含所有用于二进制文件分析的MCP工具。
所有工具都遵循标准的MCP工具规范，提供统一的接口和异常处理。
"""

# 导入工具函数
from .parse_macho_info import parse_macho_info
from .get_macho_header import get_macho_header
from .list_macho_segments import list_macho_segments
from .list_macho_sections import list_macho_sections
from .list_macho_symbols import list_macho_symbols
from .list_macho_relocations import list_macho_relocations
from .list_macho_imports import list_macho_imports
from .list_macho_exports import list_macho_exports
from .list_macho_libraries import list_macho_libraries
from .get_macho_load_commands import get_macho_load_commands
from .disassemble_macho_code import disassemble_macho_code
from .assemble_macho_code import assemble_macho_code
from .add_macho_section import add_macho_section
from .calculate_arm64_branch_target import calculate_arm64_branch_target
from .calculate_address_offset import calculate_address_offset
from .remove_macho_library import remove_macho_library
from .add_macho_library import add_macho_library
from .find_got_symbol_by_address import find_got_symbol_by_address
from .replace_macho_symbol import replace_macho_symbol


# 导出所有工具函数
__all__ = [
    "parse_macho_info",
    "get_macho_header",
    "list_macho_segments",
    "list_macho_sections",
    "list_macho_symbols",
    "list_macho_relocations",
    "list_macho_imports",
    "list_macho_exports",
    "list_macho_libraries",
    "get_macho_load_commands",
    "disassemble_macho_code",
    "assemble_macho_code",
    "add_macho_section",
    "calculate_arm64_branch_target",
    "calculate_address_offset",
    "remove_macho_library",
    "add_macho_library",
    "find_got_symbol_by_address",
    "replace_macho_symbol"
]

# 工具列表，便于动态注册
TOOLS = [
    parse_macho_info,
    get_macho_header,
    list_macho_segments,
    list_macho_sections,
    list_macho_symbols,
    list_macho_relocations,
    list_macho_imports,
    list_macho_exports,
    list_macho_libraries,
    get_macho_load_commands,
    disassemble_macho_code,
    assemble_macho_code,
    add_macho_section,
    calculate_arm64_branch_target,
    calculate_address_offset,
    remove_macho_library,
    add_macho_library,
    find_got_symbol_by_address,
    replace_macho_symbol
]
