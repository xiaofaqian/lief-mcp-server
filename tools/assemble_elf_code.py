"""
ELF 代码汇编工具
"""

from typing import Annotated, Dict, Any, Optional, Tuple
from pydantic import Field
import shutil

import lief

from .common import create_backup_path, parse_number, validate_file_path
from .elf_common import is_executable_address, parse_elf


def assemble_elf_code(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    target_address: Annotated[str, Field(
        description="要替换指令的目标虚拟地址，支持十六进制格式（如0x1000）或十进制格式"
    )],
    assembly_code: Annotated[str, Field(
        description="要插入的汇编代码，支持多行指令，例如：'mov x0, #0x1234\\nret'"
    )],
    backup_original: Annotated[bool, Field(
        description="是否备份原始文件。如果为True，将创建带时间戳的备份文件"
    )] = True,
    engine: Annotated[str, Field(
        description="汇编引擎：'auto'(优先keystone)、'lief' 或 'keystone'"
    )] = "auto",
) -> Dict[str, Any]:
    """
    在指定地址替换 ELF 指令。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        if not target_address.strip():
            return {
                "error": "目标地址不能为空",
                "suggestion": "请提供有效的虚拟地址",
            }

        if not assembly_code.strip():
            return {
                "error": "汇编代码不能为空",
                "suggestion": "请提供要插入的汇编指令",
            }

        if engine not in ["auto", "lief", "keystone"]:
            return {
                "error": f"无效的汇编引擎: {engine}",
                "suggestion": "请使用 'auto'、'lief' 或 'keystone'",
            }

        address, _, parse_error = parse_number(target_address, "auto", prefer_hex=True)
        if parse_error or address is None:
            return {
                "error": f"无效的地址格式: {target_address}",
                "suggestion": "请使用十六进制格式（如 0x1000）或十进制格式",
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
                    "error": f"无法创建备份文件: {str(exc)}",
                    "suggestion": "请检查文件权限或磁盘空间",
                }

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        if not is_executable_address(elf, address):
            return {
                "error": f"地址 {hex(address)} 不在可执行段范围内",
                "suggestion": "请检查地址是否正确，或使用 list_elf_segments 工具查看可执行段",
            }

        use_keystone = engine in ["auto", "keystone"] and _keystone_available()
        if use_keystone:
            ks, ks_error = _get_keystone_engine(elf)
            if ks_error:
                return ks_error
            try:
                encoding, _ = ks.asm(assembly_code.strip(), address)
                elf.patch_address(address, encoding)
            except Exception as exc:
                return {
                    "error": f"Keystone 汇编失败: {str(exc)}",
                    "assembly_code": assembly_code.strip(),
                    "suggestion": "请检查汇编语法或指令集是否匹配",
                }
        else:
            try:
                elf.assemble(address, assembly_code.strip())
            except Exception as exc:
                return {
                    "error": f"汇编操作失败: {str(exc)}",
                    "assembly_code": assembly_code.strip(),
                    "suggestion": "请检查汇编语法是否正确",
                }

        try:
            elf.write(file_path)
        except Exception as exc:
            return {
                "error": f"写入修改后的文件失败: {str(exc)}",
                "suggestion": "请检查文件权限或磁盘空间",
            }

        return {
            "status": "success",
            "backup_file": backup_path,
        }

    except Exception as exc:
        return {
            "error": f"汇编 ELF 代码时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "target_address": target_address,
            "assembly_code": assembly_code,
            "suggestion": "请检查文件格式和参数是否正确",
        }


def _keystone_available() -> bool:
    try:
        import keystone  # noqa: F401
        return True
    except Exception:
        return False


def _get_keystone_engine(elf: lief.ELF.Binary) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    try:
        import keystone
    except Exception:
        return None, {
            "error": "未安装 keystone-engine",
            "suggestion": "请安装 keystone-engine 以启用汇编功能",
        }

    arch = elf.header.machine_type
    if arch == lief.ELF.ARCH.AARCH64:
        return keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN), None
    if arch == lief.ELF.ARCH.ARM:
        return keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN), None
    if arch == lief.ELF.ARCH.X86_64:
        return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64), None
    if arch == lief.ELF.ARCH.I386:
        return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32), None

    return None, {
        "error": f"不支持的架构类型: {arch}",
        "suggestion": "请确认 ELF 架构是否被 keystone 支持",
    }
