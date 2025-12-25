"""
Mach-O 代码汇编工具

此工具专门用于使用 LIEF 在 Mach-O 文件的指定地址替换汇编指令。
支持多种架构的指令修改，可以在指定虚拟地址处插入新的汇编代码。
"""

from typing import Annotated, Dict, Any, List, Optional, Tuple
from pydantic import Field
import lief
import shutil

from .common import (
    create_backup_path,
    is_executable_address,
    parse_macho,
    parse_number,
    select_architecture_by_name,
    validate_file_path,
)


def assemble_macho_code(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    target_address: Annotated[str, Field(
        description="要替换指令的目标虚拟地址，支持十六进制格式（如0x100001000）或十进制格式"
    )],
    assembly_code: Annotated[str, Field(
        description="要插入的汇编代码，支持多行指令。如果是多行指令，请使用换行符分隔，例如：'mov x0, #0x1234\\nret' 或 'nop\\nnop\\nnop'"
    )],
    architecture: Annotated[str, Field(
        description="指定架构类型，如 'x86_64'、'arm64' 等。如果不指定，将使用默认架构"
    )] = "",
    backup_original: Annotated[bool, Field(
        description="是否备份原始文件。如果为True，将创建带时间戳和唯一ID的备份文件"
    )] = True,
    engine: Annotated[str, Field(
        description="汇编引擎：'auto'(优先keystone)、'lief' 或 'keystone'"
    )] = "auto",
) -> Dict[str, Any]:
    """
    在指定地址替换 Mach-O 指令
    
    该工具提供以下功能：
    - 在指定虚拟地址处替换汇编指令
    - 支持多种架构（x86_64、arm64等）
    - 支持原文件备份
    - 使用 LIEF 库，确保二进制文件完整性
    
    支持单架构和 Fat Binary 文件的指令修改。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error
        
        # 验证参数
        if not target_address.strip():
            return {
                "error": "目标地址不能为空",
                "suggestion": "请提供有效的虚拟地址，如 0x100001000"
            }
        
        if not assembly_code.strip():
            return {
                "error": "汇编代码不能为空",
                "suggestion": "请提供要插入的汇编指令，如 'mov x0, #0x1234'"
            }
        
        if engine not in ["auto", "lief", "keystone"]:
            return {
                "error": f"无效的汇编引擎: {engine}",
                "suggestion": "请使用 'auto'、'lief' 或 'keystone'",
            }

        address, _, parse_error = parse_number(target_address, "auto", prefer_hex=True)
        if parse_error:
            return {
                "error": f"无效的地址格式: {target_address}",
                "suggestion": "请使用十六进制格式（如 0x100001000）或十进制格式"
            }
        
        # 备份原始文件
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
            except Exception as e:
                return {
                    "error": f"无法创建备份文件: {str(e)}",
                    "suggestion": "请检查文件权限或磁盘空间"
                }
        
        fat_binary, parse_error = parse_macho(file_path)
        if parse_error:
            return parse_error
        
        # 选择架构
        binary = select_architecture_by_name(fat_binary, architecture)
        if binary is None:
            available_archs = [str(b.header.cpu_type) for b in fat_binary]
            return {
                "error": f"未找到指定的架构: {architecture}",
                "available_architectures": available_archs,
                "suggestion": f"请使用可用的架构之一: {', '.join(available_archs)}"
            }
        
        # 验证地址是否在有效范围内
        if not is_executable_address(binary, address):
            return {
                "error": f"地址 {hex(address)} 不在有效的代码段范围内",
                "suggestion": "请检查地址是否正确，或使用 list_macho_segments 工具查看可用的代码段"
            }
        
        use_keystone = engine in ["auto", "keystone"] and _keystone_available()
        if use_keystone:
            ks, ks_error = _get_keystone_engine(binary)
            if ks_error:
                return ks_error
            try:
                encoding, _ = ks.asm(assembly_code.strip(), address)
                binary.patch_address(address, encoding)
            except Exception as e:
                return {
                    "error": f"Keystone 汇编失败: {str(e)}",
                    "assembly_code": assembly_code.strip(),
                    "suggestion": "请检查汇编语法是否正确，或尝试简化指令"
                }
        else:
            try:
                binary.assemble(address, assembly_code.strip())
            except Exception as e:
                return {
                    "error": f"汇编操作失败: {str(e)}",
                    "assembly_code": assembly_code.strip(),
                    "suggestion": "请检查汇编语法是否正确，或尝试简化指令"
                }
        
        # 写入修改后的文件
        try:
            if len(fat_binary) == 1:
                # 单架构文件
                binary.write(file_path)
            else:
                # Fat Binary 文件
                fat_binary.write(file_path)
                
        except Exception as e:
            return {
                "error": f"写入修改后的文件失败: {str(e)}",
                "suggestion": "请检查文件权限或磁盘空间"
            }
        
        # 获取修改后的指令用于返回
        modified_instructions = _get_modified_instructions(binary, address, 5)
        
        # 构建简化的结果
        result = {
            "status": "success",
            "modified_instructions": modified_instructions
        }
        
        if backup_path:
            result["backup_file"] = backup_path
        
        return result
        
    except Exception as e:
        return {
            "error": f"汇编代码时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "target_address": target_address,
            "assembly_code": assembly_code,
            "suggestion": "请检查文件格式和参数是否正确，或联系技术支持"
        }


def _get_modified_instructions(binary: lief.MachO.Binary, address: int, count: int = 5) -> str:
    """获取修改后的指令，返回简单的字符串格式"""
    
    instructions = []
    
    try:
        instruction_iter = binary.disassemble(address)
        
        for i, inst in enumerate(instruction_iter):
            if i >= count:
                break
            
            # 格式化为简单的字符串：地址 指令（移除重复的地址）
            instruction_str = f"{hex(inst.address)} {inst.mnemonic}"
            if hasattr(inst, 'op_str') and inst.op_str:
                instruction_str += f" {inst.op_str}"
            instructions.append(instruction_str)
        
    except Exception as e:
        # 如果无法获取指令，返回错误信息
        return f"错误: 无法获取修改后的指令 - {str(e)}"
    
    # 将指令列表连接为多行字符串
    return "\n".join(instructions)


def _keystone_available() -> bool:
    try:
        import keystone  # noqa: F401
        return True
    except Exception:
        return False


def _get_keystone_engine(binary: lief.MachO.Binary) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    try:
        import keystone
    except Exception:
        return None, {
            "error": "未安装 keystone-engine",
            "suggestion": "请安装 keystone-engine 以启用汇编功能",
        }

    cpu = str(binary.header.cpu_type).upper()
    if "ARM64" in cpu:
        return keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN), None
    if "ARM" in cpu:
        return keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN), None
    if "X86_64" in cpu or "X86_64H" in cpu:
        return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64), None
    if "X86" in cpu:
        return keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32), None

    return None, {
        "error": f"不支持的架构类型: {binary.header.cpu_type}",
        "suggestion": "请确认架构是否被 keystone 支持",
    }
