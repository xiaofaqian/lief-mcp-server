"""
ELF 依赖库列表工具
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief

from .common import compile_regex_filter, paginate_items, validate_file_path
from .elf_common import parse_elf


def list_elf_libraries(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    name_filter: Annotated[Optional[str], Field(
        description="依赖库名称过滤器，支持正则表达式匹配，例如：'libc' 或 '.*\\.so$'"
    )] = None,
    offset: Annotated[int, Field(description="起始位置偏移量，从第几个依赖库开始返回（从0开始计数）", ge=0)] = 0,
    count: Annotated[int, Field(description="返回的依赖库数量，最大100条，0表示返回所有剩余依赖库", ge=0, le=100)] = 20,
    simplified: Annotated[bool, Field(description="是否使用简化模式，仅返回库名列表")] = True,
) -> Dict[str, Any]:
    """
    列出 ELF 文件中的 DT_NEEDED 依赖库以及 RPATH/RUNPATH/SONAME 信息。
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

        libraries: List[Dict[str, Any]] = []
        for entry in elf.dynamic_entries:
            tag = str(entry.tag).split(".")[-1]
            if tag != "NEEDED":
                continue
            name = getattr(entry, "name", "")
            if regex_filter and not regex_filter.search(name):
                continue
            if simplified:
                libraries.append({"name": name})
            else:
                libraries.append({
                    "name": name,
                    "tag": tag,
                })

        filtered_count = len(libraries)
        paged_libraries, pagination_info, pagination_error = paginate_items(libraries, offset, count)
        if pagination_error:
            pagination_error.update({
                "error": pagination_error["error"].replace("过滤后的总数", "过滤后的库依赖总数"),
            })
            return pagination_error

        rpath = None
        runpath = None
        soname = None
        for entry in elf.dynamic_entries:
            tag = str(entry.tag).split(".")[-1]
            if tag == "RPATH":
                rpath = getattr(entry, "name", None)
            elif tag == "RUNPATH":
                runpath = getattr(entry, "name", None)
            elif tag == "SONAME":
                soname = getattr(entry, "name", None)

        return {
            "file_path": file_path,
            "format": "ELF",
            "soname": soname,
            "rpath": rpath,
            "runpath": runpath,
            "total_libraries": filtered_count,
            "libraries": paged_libraries,
            "pagination_info": {
                "offset": offset,
                "count": len(paged_libraries),
                "has_more": pagination_info["has_more"],
                "next_offset": pagination_info["next_offset"],
            },
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 依赖库信息时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
