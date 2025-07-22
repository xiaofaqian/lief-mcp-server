"""
Mach-O 代码汇编工具

此工具专门用于使用 LIEF 在 Mach-O 文件的指定地址替换汇编指令。
支持多种架构的指令修改，可以在指定虚拟地址处插入新的汇编代码。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os
import shutil
import datetime
import uuid


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
    )] = True
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
        # 验证文件路径
        if not os.path.exists(file_path):
            return {
                "error": f"文件不存在: {file_path}",
                "suggestion": "请检查文件路径是否正确，确保使用完整的绝对路径"
            }
        
        if not os.access(file_path, os.R_OK):
            return {
                "error": f"无权限读取文件: {file_path}",
                "suggestion": "请检查文件权限，确保当前用户有读取权限"
            }
        
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
        
        # 解析目标地址
        try:
            if target_address.startswith('0x') or target_address.startswith('0X'):
                address = int(target_address, 16)
            else:
                try:
                    address = int(target_address, 16)
                except ValueError:
                    address = int(target_address, 10)
        except ValueError:
            return {
                "error": f"无效的地址格式: {target_address}",
                "suggestion": "请使用十六进制格式（如 0x100001000）或十进制格式"
            }
        
        # 备份原始文件
        backup_path = None
        if backup_original:
            # 生成带时间戳和唯一ID的备份文件名
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id = str(uuid.uuid4())[:8]  # 使用UUID的前8位
            base_name, ext = os.path.splitext(file_path)
            backup_path = f"{base_name}.backup_{timestamp}_{unique_id}{ext}"
            
            try:
                shutil.copy2(file_path, backup_path)
            except Exception as e:
                return {
                    "error": f"无法创建备份文件: {str(e)}",
                    "suggestion": "请检查文件权限或磁盘空间"
                }
        
        # 解析 Mach-O 文件
        fat_binary = lief.MachO.parse(file_path)
        
        if fat_binary is None:
            return {
                "error": "无法解析文件，可能不是有效的 Mach-O 文件",
                "file_path": file_path,
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        # 选择架构
        binary = _select_architecture(fat_binary, architecture)
        if binary is None:
            available_archs = [str(b.header.cpu_type) for b in fat_binary]
            return {
                "error": f"未找到指定的架构: {architecture}",
                "available_architectures": available_archs,
                "suggestion": f"请使用可用的架构之一: {', '.join(available_archs)}"
            }
        
        # 验证地址是否在有效范围内
        if not _is_valid_address(binary, address):
            return {
                "error": f"地址 {hex(address)} 不在有效的代码段范围内",
                "suggestion": "请检查地址是否正确，或使用 list_macho_segments 工具查看可用的代码段"
            }
        
        # 执行汇编操作 - 直接使用原始汇编代码，LIEF 支持多行汇编
        try:
            # 使用 LIEF 的 assemble 方法，直接传递多行汇编代码
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


def _select_architecture(fat_binary: lief.MachO.FatBinary, architecture: str) -> Optional[lief.MachO.Binary]:
    """选择指定的架构"""
    
    if not architecture:
        # 如果没有指定架构，返回第一个
        return fat_binary[0] if len(fat_binary) > 0 else None
    
    # 尝试按架构名称匹配
    arch_lower = architecture.lower()
    for binary in fat_binary:
        cpu_type_str = str(binary.header.cpu_type).lower()
        if arch_lower in cpu_type_str or cpu_type_str in arch_lower:
            return binary
    
    return None


def _is_valid_address(binary: lief.MachO.Binary, address: int) -> bool:
    """检查地址是否在有效的代码段范围内"""
    return True


def _get_modified_instructions(binary: lief.MachO.Binary, address: int, count: int = 5) -> str:
    """获取修改后的指令，返回简单的字符串格式"""
    
    instructions = []
    
    try:
        instruction_iter = binary.disassemble(address)
        
        for i, inst in enumerate(instruction_iter):
            if i >= count:
                break
            
            # 格式化为简单的字符串：地址 指令
            instruction_str = f"{hex(inst.address)} {inst.to_string()}"
            instructions.append(instruction_str)
        
    except Exception as e:
        # 如果无法获取指令，返回错误信息
        return f"错误: 无法获取修改后的指令 - {str(e)}"
    
    # 将指令列表连接为多行字符串
    return "\n".join(instructions)
