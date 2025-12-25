"""
ELF 段信息列表工具
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief

from .common import format_size, validate_file_path
from .elf_common import parse_elf, parse_segment_flags


def list_elf_segments(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )]
) -> Dict[str, Any]:
    """
    列出 ELF 文件中的 Program Headers（段）信息。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        segments_info: List[Dict[str, Any]] = []
        for segment in elf.segments:
            try:
                sections = getattr(segment, "sections", [])
                segments_info.append({
                    "type": str(segment.type),
                    "flags": {
                        "raw": str(segment.flags),
                        "parsed": parse_segment_flags(segment.flags),
                    },
                    "virtual_address": hex(segment.virtual_address),
                    "physical_address": hex(segment.physical_address),
                    "virtual_size": {
                        "value": segment.virtual_size,
                        "human_readable": format_size(segment.virtual_size),
                    },
                    "physical_size": {
                        "value": segment.physical_size,
                        "human_readable": format_size(segment.physical_size),
                    },
                    "file_offset": segment.file_offset,
                    "alignment": segment.alignment,
                    "sections_count": len(sections),
                })
            except Exception as exc:
                segments_info.append({
                    "error": f"解析段信息时发生错误: {str(exc)}"
                })

        return {
            "file_path": file_path,
            "format": "ELF",
            "segments_count": len(segments_info),
            "segments": segments_info,
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 段信息时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
