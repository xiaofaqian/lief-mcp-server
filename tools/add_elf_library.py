"""
ELF 添加依赖库工具
"""

from typing import Annotated, Dict, Any, Optional
from pydantic import Field
import shutil

import lief

from .common import create_backup_path, validate_file_path
from .elf_common import parse_elf


def add_elf_library(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    library_name: Annotated[str, Field(
        description="要添加的动态库名称，例如：libdemo.so"
    )],
    backup_original: Annotated[bool, Field(description="是否备份原始文件")] = True,
    output_path: Annotated[Optional[str], Field(description="输出文件路径。不指定则覆盖原文件")] = None,
) -> Dict[str, Any]:
    """
    向 ELF 文件添加 DT_NEEDED 依赖库。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        if not library_name.strip():
            return {
                "error": "库名称不能为空",
                "suggestion": "请提供有效的库名称，例如 libdemo.so",
            }

        backup_path = None
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
                    "error": f"备份文件失败: {str(exc)}",
                    "suggestion": "请检查磁盘空间和权限",
                }

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        if elf.has_library(library_name):
            return {
                "success": False,
                "message": f"库 {library_name} 已存在",
                "file_path": file_path,
                "library_name": library_name,
            }

        elf.add_library(library_name)
        final_path = output_path or file_path
        elf.write(final_path)

        return {
            "success": True,
            "message": f"成功添加库依赖: {library_name}",
            "file_path": file_path,
            "output_path": final_path,
            "backup_file": backup_path,
        }

    except Exception as exc:
        return {
            "error": f"添加 ELF 依赖库时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "library_name": library_name,
            "suggestion": "请检查文件格式是否正确",
        }
