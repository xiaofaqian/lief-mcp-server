"""
ELF 重定位信息列表工具
"""

from typing import Annotated, Optional, Dict, Any, List
from pydantic import Field
import lief

from .common import compile_regex_filter, paginate_items, validate_file_path
from .elf_common import parse_elf


def list_elf_relocations(
    file_path: Annotated[str, Field(description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so")],
    offset: Annotated[int, Field(description="起始位置偏移量，从第几个重定位项开始返回（从0开始计数）", ge=0)] = 0,
    count: Annotated[int, Field(description="返回的重定位项数量，最大100条，0表示返回所有剩余重定位项", ge=0, le=100)] = 20,
    symbol_filter: Annotated[Optional[str], Field(description="符号名称过滤器，支持正则表达式匹配")] = None,
    output_format: Annotated[str, Field(description="输出格式：'text' 或 'json'")] = "json",
) -> Any:
    """
    列出 ELF 文件中的重定位信息，支持分页与过滤。
    """
    try:
        if output_format not in ["text", "json"]:
            return {"error": f"无效的输出格式: {output_format}", "suggestion": "请使用 'text' 或 'json'"}

        path_error = validate_file_path(file_path)
        if path_error:
            return _format_error(path_error, output_format)

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return _format_error(parse_error, output_format)

        regex_filter, filter_error = compile_regex_filter(symbol_filter)
        if filter_error:
            return _format_error(filter_error, output_format)

        relocations: List[Dict[str, Any]] = []
        for relocation in list(getattr(elf, "relocations", [])) + list(getattr(elf, "pltgot_relocations", [])):
            try:
                symbol_name = ""
                if getattr(relocation, "has_symbol", False) and relocation.symbol:
                    symbol_name = relocation.symbol.name or ""
                if regex_filter and not (regex_filter.search(symbol_name) or regex_filter.search(str(relocation))):
                    continue
                relocations.append({
                    "address": relocation.address,
                    "address_hex": hex(relocation.address),
                    "type": str(relocation.type),
                    "addend": getattr(relocation, "addend", None),
                    "purpose": str(getattr(relocation, "purpose", "")),
                    "symbol": symbol_name,
                })
            except Exception as exc:
                relocations.append({
                    "error": f"解析重定位项时发生错误: {str(exc)}"
                })

        total_relocations = len(relocations)
        paged_relocations, pagination_info, pagination_error = paginate_items(relocations, offset, count)
        if pagination_error:
            return _format_error(pagination_error, output_format)

        if output_format == "text":
            lines = [
                f"文件: {file_path}",
                f"总重定位项数量: {total_relocations}",
            ]
            if symbol_filter:
                lines.append(f"过滤条件: {symbol_filter}")
            lines.append("")
            lines.append("地址        类型                 Addend   符号")
            lines.append("-" * 72)
            for item in paged_relocations:
                if "error" in item:
                    lines.append(item["error"])
                    continue
                lines.append(
                    f"{item['address_hex']:<10} {item['type'][:20]:<20} "
                    f"{str(item.get('addend', '')):<8} {item.get('symbol', '')}"
                )
            return "\n".join(lines)

        return {
            "file_path": file_path,
            "format": "ELF",
            "total_relocations": total_relocations,
            "pagination_info": {
                "offset": offset,
                "count": len(paged_relocations),
                "has_more": pagination_info["has_more"],
                "next_offset": pagination_info["next_offset"],
            },
            "relocations": paged_relocations,
        }

    except Exception as exc:
        return _format_error({"error": f"解析 ELF 重定位时发生未预期的错误: {str(exc)}"}, output_format)


def _format_error(error_info: Dict[str, Any], output_format: str) -> Any:
    if output_format == "json":
        return error_info
    message = error_info.get("error", "未知错误")
    suggestion = error_info.get("suggestion")
    if suggestion:
        return f"错误：{message}\n建议：{suggestion}"
    return f"错误：{message}"
