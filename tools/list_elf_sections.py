"""
ELF 节信息列表工具
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief

from .common import format_size, validate_file_path
from .elf_common import parse_elf, parse_section_flags


def list_elf_sections(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )]
) -> Dict[str, Any]:
    """
    列出 ELF 文件中的 Section Headers（节）信息。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        sections_info: List[Dict[str, Any]] = []
        for section in elf.sections:
            try:
                sections_info.append({
                    "name": section.name,
                    "type": str(section.type),
                    "flags": {
                        "raw": str(section.flags),
                        "parsed": parse_section_flags(section),
                    },
                    "virtual_address": hex(section.virtual_address),
                    "offset": section.offset,
                    "size": {
                        "value": section.size,
                        "human_readable": format_size(section.size),
                    },
                    "alignment": section.alignment,
                    "entry_size": getattr(section, "entry_size", 0),
                })
            except Exception as exc:
                sections_info.append({
                    "name": getattr(section, "name", "unknown"),
                    "error": f"解析节信息时发生错误: {str(exc)}",
                })

        return {
            "file_path": file_path,
            "format": "ELF",
            "sections_count": len(sections_info),
            "sections": sections_info,
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 节信息时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
