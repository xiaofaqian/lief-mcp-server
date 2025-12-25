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
from .parse_elf_info import parse_elf_info
from .get_elf_header import get_elf_header
from .list_elf_segments import list_elf_segments
from .list_elf_sections import list_elf_sections
from .list_elf_symbols import list_elf_symbols
from .list_elf_relocations import list_elf_relocations
from .list_elf_imports import list_elf_imports
from .list_elf_exports import list_elf_exports
from .list_elf_libraries import list_elf_libraries
from .get_elf_dynamic import get_elf_dynamic
from .disassemble_elf_code import disassemble_elf_code
from .assemble_elf_code import assemble_elf_code
from .add_elf_section import add_elf_section
from .add_elf_library import add_elf_library
from .remove_elf_library import remove_elf_library
from .find_elf_got_symbol_by_address import find_elf_got_symbol_by_address
from .replace_elf_symbol import replace_elf_symbol


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
    "replace_macho_symbol",
    "parse_elf_info",
    "get_elf_header",
    "list_elf_segments",
    "list_elf_sections",
    "list_elf_symbols",
    "list_elf_relocations",
    "list_elf_imports",
    "list_elf_exports",
    "list_elf_libraries",
    "get_elf_dynamic",
    "disassemble_elf_code",
    "assemble_elf_code",
    "add_elf_section",
    "add_elf_library",
    "remove_elf_library",
    "find_elf_got_symbol_by_address",
    "replace_elf_symbol"
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
    replace_macho_symbol,
    parse_elf_info,
    get_elf_header,
    list_elf_segments,
    list_elf_sections,
    list_elf_symbols,
    list_elf_relocations,
    list_elf_imports,
    list_elf_exports,
    list_elf_libraries,
    get_elf_dynamic,
    disassemble_elf_code,
    assemble_elf_code,
    add_elf_section,
    add_elf_library,
    remove_elf_library,
    find_elf_got_symbol_by_address,
    replace_elf_symbol
]
