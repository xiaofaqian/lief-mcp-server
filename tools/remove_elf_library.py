"""
ELF 移除依赖库工具
"""

from typing import Annotated, Dict, Any
from pydantic import Field
import shutil

import lief

from .common import create_backup_path, validate_file_path
from .elf_common import parse_elf


def remove_elf_library(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    library_name: Annotated[str, Field(
        description="要移除的依赖库名称，例如：libdemo.so"
    )],
    backup_original: Annotated[bool, Field(description="是否备份原始文件")] = True,
) -> Dict[str, Any]:
    """
    从 ELF 文件中移除 DT_NEEDED 依赖库。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

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

        if not elf.has_library(library_name):
            return {
                "error": f"未找到指定的依赖库: {library_name}",
                "suggestion": "请检查库名称是否正确，可以使用 list_elf_libraries 查看",
            }

        elf.remove_library(library_name)
        elf.write(file_path)

        return {
            "success": True,
            "message": f"成功移除依赖库: {library_name}",
            "file_path": file_path,
            "backup_file": backup_path,
        }

    except Exception as exc:
        return {
            "error": f"移除 ELF 依赖库时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "library_name": library_name,
            "suggestion": "请检查文件格式是否正确",
        }
