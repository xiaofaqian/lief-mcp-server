"""
为 ELF 文件添加新的代码节工具
"""

from typing import Annotated, Dict, Any, Optional, List
from pydantic import Field
import shutil

import lief

from .common import create_backup_path, format_size, validate_file_path
from .elf_common import parse_elf


def add_elf_section(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    section_name: Annotated[str, Field(
        description="新节的名称，例如：.text.inject、.mycode 等"
    )] = ".text.inject",
    size: Annotated[int, Field(
        description="节大小（字节），必须大于0",
        gt=0
    )] = 4096,
    fill_type: Annotated[str, Field(
        description="填充类型：'empty'(零字节填充) 或 'nop'(NOP指令填充)"
    )] = "nop",
    backup_original: Annotated[bool, Field(
        description="是否备份原始文件"
    )] = True,
    output_path: Annotated[Optional[str], Field(
        description="输出文件路径。不指定则覆盖原文件"
    )] = None,
) -> Dict[str, Any]:
    """
    为 ELF 文件添加新节，支持 NOP 或空白填充。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        if fill_type not in ["empty", "nop"]:
            return {
                "error": f"无效的填充类型: {fill_type}",
                "suggestion": "填充类型必须是 'empty' 或 'nop'",
            }

        if backup_original:
            backup_path = create_backup_path(
                file_path,
                suffix="backup",
                separator=".",
                timestamp_sep="_",
                include_uuid=True,
                insert_before_ext=True,
            )
            try:
                shutil.copy2(file_path, backup_path)
            except Exception as exc:
                return {
                    "error": f"无法创建备份文件: {str(exc)}",
                    "suggestion": "请检查文件权限或磁盘空间",
                }
        else:
            backup_path = None

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        content = _generate_fill_content(fill_type, size, str(elf.header.machine_type))

        section = lief.ELF.Section(section_name)
        section.type = lief.ELF.Section.TYPE.PROGBITS
        section.content = content
        section.flags = lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.EXECINSTR

        added = elf.add(section)
        if added is None:
            return {
                "error": "添加节失败",
                "suggestion": "可能是节名称冲突或内部错误",
            }

        final_path = output_path or file_path
        elf.write(final_path)

        return {
            "success": True,
            "file_path": file_path,
            "output_path": final_path,
            "backup_file": backup_path,
            "section_info": {
                "name": section_name,
                "size": size,
                "size_formatted": format_size(size),
                "virtual_address": hex(added.virtual_address),
                "offset": added.offset,
            },
        }

    except Exception as exc:
        return {
            "error": f"添加 ELF 节时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确",
        }


def _generate_fill_content(fill_type: str, size: int, machine: str) -> List[int]:
    if fill_type == "empty":
        return [0x00] * size
    if "AARCH64" in machine.upper():
        nop = [0x1F, 0x20, 0x03, 0xD5]
    elif "X86_64" in machine.upper() or "X86" in machine.upper():
        nop = [0x90]
    else:
        nop = [0x00]
    content: List[int] = []
    while len(content) < size:
        content.extend(nop)
    return content[:size]
