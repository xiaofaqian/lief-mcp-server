"""
ELF 导入符号信息列表工具

以简洁表格格式返回：索引|所在库|符号名|地址
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief

from .common import compile_regex_filter, paginate_items, validate_file_path
from .elf_common import parse_elf


def list_elf_imports(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    offset: Annotated[int, Field(description="起始位置偏移量，从第几个导入项开始返回（从0开始计数）", ge=0)] = 0,
    count: Annotated[int, Field(description="返回的导入项数量，最大100条，0表示返回所有剩余导入项", ge=0, le=100)] = 20,
    name_filter: Annotated[Optional[str], Field(description="导入项名称过滤器，支持正则表达式匹配")] = None,
) -> Dict[str, Any]:
    """
    列出 ELF 文件中的导入符号。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        regex_filter, filter_error = compile_regex_filter(name_filter)
        if filter_error:
            return filter_error

        relocation_map: Dict[str, str] = {}
        for relocation in list(getattr(elf, "relocations", [])) + list(getattr(elf, "pltgot_relocations", [])):
            if not getattr(relocation, "has_symbol", False):
                continue
            symbol = relocation.symbol
            if not symbol or not symbol.name:
                continue
            if symbol.name not in relocation_map:
                relocation_map[symbol.name] = hex(relocation.address)

        imports: List[Dict[str, Any]] = []
        for symbol in elf.dynamic_symbols:
            if not getattr(symbol, "imported", False):
                continue
            name = symbol.name
            if regex_filter and not regex_filter.search(name):
                continue
            imports.append({
                "symbol": name,
                "library": "unknown",
                "address": relocation_map.get(name, "0x0"),
            })

        filtered_count = len(imports)
        paged_imports, pagination_info, pagination_error = paginate_items(imports, offset, count)
        if pagination_error:
            pagination_error.update({
                "error": pagination_error["error"].replace("过滤后的总数", "过滤后的导入项总数"),
            })
            return pagination_error

        import_lines: List[str] = []
        for i, item in enumerate(paged_imports, start=offset + 1):
            import_lines.append(f"{i}|{item['library']}|{item['symbol']}|{item['address']}")

        return {
            "file_path": file_path,
            "format": "ELF",
            "total_imports": filtered_count,
            "libraries": list(getattr(elf, "libraries", [])),
            "imports": import_lines,
            "pagination_info": {
                "offset": offset,
                "count": len(paged_imports),
                "has_more": pagination_info["has_more"],
                "next_offset": pagination_info["next_offset"],
            },
            "note": "ELF 符号通常不携带所属库信息，library 字段为 unknown",
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 导入信息时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
