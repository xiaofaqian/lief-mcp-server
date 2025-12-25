"""
通过地址查找 ELF GOT/重定位符号的工具
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief

from .common import parse_number, validate_file_path
from .elf_common import parse_elf


def find_elf_got_symbol_by_address(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    target_address: Annotated[str, Field(
        description="要查找的目标地址，支持十六进制格式（如0x1000）或十进制格式"
    )],
    search_range: Annotated[int, Field(
        description="搜索范围（字节），0表示精确匹配，大于0表示在目标地址前后指定范围内搜索",
        ge=0
    )] = 0,
) -> Dict[str, Any]:
    """
    根据地址查找 ELF 中 GOT/PLT 相关的重定位符号信息。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        target_addr, _, parse_error = parse_number(target_address, "auto", prefer_hex=True)
        if parse_error or target_addr is None:
            return {
                "error": f"无效的地址格式: {target_address}",
                "suggestion": "请使用十六进制格式（如0x1000）或十进制格式",
            }

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        relocations = list(getattr(elf, "pltgot_relocations", [])) + list(getattr(elf, "relocations", []))
        exact_matches: List[Dict[str, Any]] = []
        range_matches: List[Dict[str, Any]] = []

        for relocation in relocations:
            address = relocation.address
            symbol_name = ""
            if getattr(relocation, "has_symbol", False) and relocation.symbol:
                symbol_name = relocation.symbol.name or ""
            info = {
                "address": address,
                "address_hex": hex(address),
                "type": str(relocation.type),
                "purpose": str(getattr(relocation, "purpose", "")),
                "symbol": symbol_name,
                "addend": getattr(relocation, "addend", None),
            }
            if address == target_addr:
                exact_matches.append(info)
            elif search_range > 0 and abs(address - target_addr) <= search_range:
                range_matches.append(info)

        return {
            "file_path": file_path,
            "target_address": {
                "input": target_address,
                "parsed": target_addr,
                "hex": hex(target_addr),
            },
            "search_range": search_range,
            "exact_matches": exact_matches,
            "range_matches": range_matches,
        }

    except Exception as exc:
        return {
            "error": f"查找 ELF 符号时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "target_address": target_address,
            "suggestion": "请检查文件格式是否正确",
        }
