"""
ELF 导出符号信息列表工具
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief

from .common import compile_regex_filter, paginate_items, validate_file_path
from .elf_common import parse_elf


def list_elf_exports(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    offset: Annotated[int, Field(description="起始位置偏移量，从第几个导出符号开始返回（从0开始计数）", ge=0)] = 0,
    count: Annotated[int, Field(description="返回的导出符号数量，最大100条，0表示返回所有剩余导出符号", ge=0, le=100)] = 20,
    name_filter: Annotated[Optional[str], Field(description="导出符号名称过滤器，支持正则表达式匹配")] = None,
) -> Dict[str, Any]:
    """
    列出 ELF 文件中的导出符号。
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

        exports: List[Dict[str, Any]] = []
        for symbol in elf.dynamic_symbols:
            if not getattr(symbol, "exported", False):
                continue
            name = symbol.name
            if regex_filter and not regex_filter.search(name):
                continue
            exports.append({
                "name": name,
                "value": {
                    "address": symbol.value,
                    "hex": hex(symbol.value),
                },
                "size": symbol.size,
                "binding": str(symbol.binding),
                "type": str(symbol.type),
                "visibility": str(symbol.visibility),
            })

        filtered_count = len(exports)
        paged_exports, pagination_info, pagination_error = paginate_items(exports, offset, count)
        if pagination_error:
            pagination_error.update({
                "error": pagination_error["error"].replace("过滤后的总数", "过滤后的导出符号总数"),
            })
            return pagination_error

        return {
            "file_path": file_path,
            "format": "ELF",
            "pagination_info": {
                "total_exports": filtered_count,
                "requested_offset": offset,
                "requested_count": count,
                "returned_count": pagination_info["returned_count"],
                "has_more": pagination_info["has_more"],
                "next_offset": pagination_info["next_offset"],
            },
            "filter_info": {
                "name_filter": name_filter,
                "filter_applied": name_filter is not None,
                "filter_valid": regex_filter is not None,
            },
            "exports": paged_exports,
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 导出符号信息时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
