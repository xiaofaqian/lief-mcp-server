"""
ELF 文件信息解析工具

解析 ELF 文件的基本信息，包括架构、文件类型、入口点、段节统计、动态库依赖等。
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import os
import lief

from .common import format_size_compact, validate_file_path
from .elf_common import get_android_ident, get_build_id, parse_elf


def parse_elf_info(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )]
) -> Dict[str, Any]:
    """
    解析 ELF 文件基本信息，返回结构化数据。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        file_stat = os.stat(file_path)
        file_size = file_stat.st_size

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            parse_error["file_size"] = file_size
            return parse_error

        header = elf.header
        result: Dict[str, Any] = {
            "file_path": file_path,
            "file_size": file_size,
            "file_size_human": format_size_compact(file_size),
            "format": "ELF",
            "architecture": str(getattr(header, "machine_type", "")),
            "class": str(header.identity_class),
            "endianness": str(header.identity_data),
            "file_type": str(header.file_type),
            "entrypoint": hex(header.entrypoint),
            "entrypoint_decimal": header.entrypoint,
            "statistics": {
                "segments_count": len(elf.segments),
                "sections_count": len(elf.sections),
                "symbols_count": len(elf.symbols),
                "dynamic_symbols_count": len(getattr(elf, "dynamic_symbols", [])),
                "relocations_count": len(getattr(elf, "relocations", [])),
                "pltgot_relocations_count": len(getattr(elf, "pltgot_relocations", [])),
            },
        }

        if hasattr(elf, "libraries"):
            result["libraries"] = list(elf.libraries)

        build_id = get_build_id(elf)
        if build_id:
            result["build_id"] = build_id

        android_ident = get_android_ident(elf)
        if android_ident:
            result["android_ident"] = android_ident

        return result

    except Exception as exc:
        return {
            "error": f"解析 ELF 文件时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
