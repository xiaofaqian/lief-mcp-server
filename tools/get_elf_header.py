"""
ELF 头部信息获取工具
"""

from typing import Annotated, Dict, Any
from pydantic import Field
import lief

from .common import validate_file_path
from .elf_common import parse_elf


def get_elf_header(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )]
) -> Dict[str, Any]:
    """
    获取 ELF 文件头部信息。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        header = elf.header
        return {
            "file_path": file_path,
            "identity": {
                "class": str(getattr(header, "identity_class", "")),
                "data": str(getattr(header, "identity_data", "")),
                "version": str(getattr(header, "identity_version", "")),
                "os_abi": str(getattr(header, "identity_os_abi", "")),
                "abi_version": getattr(header, "identity_abi_version", None),
            },
            "file_type": str(getattr(header, "file_type", "")),
            "machine": str(getattr(header, "machine_type", "")),
            "entrypoint": {
                "value": header.entrypoint,
                "hex": hex(header.entrypoint),
            },
            "program_headers": {
                "offset": header.program_header_offset,
                "size": header.program_header_size,
                "count": header.numberof_segments,
            },
            "section_headers": {
                "offset": header.section_header_offset,
                "size": header.section_header_size,
                "count": header.numberof_sections,
                "string_table_index": header.section_name_table_idx,
            },
            "flags": getattr(header, "flags", None),
            "header_size": header.header_size,
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 头部时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
