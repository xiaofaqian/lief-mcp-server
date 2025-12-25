"""
ELF 符号替换工具（基于动态符号重命名）
"""

from typing import Annotated, Dict, Any, Optional
from pydantic import Field
import shutil

import lief

from .common import create_backup_path, validate_file_path
from .elf_common import parse_elf


def replace_elf_symbol(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    original_symbol: Annotated[str, Field(
        description="要替换的原始符号名称，例如：malloc"
    )],
    replacement_symbol: Annotated[str, Field(
        description="替换后的符号名称，例如：my_malloc"
    )],
    custom_library_name: Annotated[Optional[str], Field(
        description="可选：要添加的依赖库名称，例如：libhook.so"
    )] = None,
    rewrite_relocations: Annotated[bool, Field(
        description="是否改写重定位/PLT-GOT 关联到替换符号。默认启用"
    )] = True,
    rename_original: Annotated[bool, Field(
        description="是否重命名原始符号，避免名称冲突。默认关闭"
    )] = False,
    backup_original: Annotated[bool, Field(description="是否备份原始文件")] = True,
) -> Dict[str, Any]:
    """
    通过改写重定位/PLT-GOT 关联实现替换，必要时添加依赖库。
    """
    try:
        path_error = validate_file_path(file_path, require_write=True)
        if path_error:
            return path_error

        if not original_symbol.strip() or not replacement_symbol.strip():
            return {
                "error": "原始符号和替换符号不能为空",
                "suggestion": "请提供有效的符号名称",
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

        target_symbol = None
        for sym in elf.dynamic_symbols:
            if sym.name == original_symbol:
                target_symbol = sym
                break

        if not target_symbol:
            return {
                "error": f"未找到符号 '{original_symbol}' 的动态符号条目",
                "suggestion": "请确认符号是否存在于 .dynsym",
            }

        if custom_library_name:
            if not elf.has_library(custom_library_name):
                elf.add_library(custom_library_name)

        replacement = None
        for sym in elf.dynamic_symbols:
            if sym.name == replacement_symbol:
                replacement = sym
                break

        if replacement is None:
            replacement = lief.ELF.Symbol()
            replacement.name = replacement_symbol
            replacement.value = 0
            replacement.size = 0
            replacement.binding = target_symbol.binding
            replacement.type = target_symbol.type
            replacement.visibility = target_symbol.visibility
            replacement.shndx = 0
            replacement = elf.add_dynamic_symbol(replacement)

        modified_relocations = 0
        if rewrite_relocations:
            for relocation in list(getattr(elf, "relocations", [])) + list(getattr(elf, "pltgot_relocations", [])):
                if getattr(relocation, "has_symbol", False) and relocation.symbol:
                    if relocation.symbol.name == original_symbol:
                        relocation.symbol = replacement
                        modified_relocations += 1

        if rename_original:
            target_symbol.name = f"{original_symbol}_orig"

        elf.write(file_path)

        return {
            "success": True,
            "file_path": file_path,
            "backup_file": backup_path,
            "original_symbol": original_symbol,
            "replacement_symbol": replacement_symbol,
            "custom_library_name": custom_library_name,
            "rewrite_relocations": rewrite_relocations,
            "modified_relocations": modified_relocations,
            "renamed_original": rename_original,
        }

    except Exception as exc:
        return {
            "error": f"替换 ELF 符号时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确",
        }
