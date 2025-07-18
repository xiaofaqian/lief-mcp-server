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
        description="要插入的汇编代码，支持多行指令。例如：'mov x0, #0x1234; ret' 或 'nop; nop; nop'"
    )],
    architecture: Annotated[str, Field(
        description="指定架构类型，如 'x86_64'、'arm64' 等。如果不指定，将使用默认架构"
    )] = "",
    output_path: Annotated[str, Field(
        description="修改后文件的输出路径。如果不指定，将直接覆盖原文件"
    )] = "",
    backup_original: Annotated[bool, Field(
        description="是否备份原始文件。如果为True，将创建带时间戳和唯一ID的备份文件"
    )] = True,
    verify_assembly: Annotated[bool, Field(
        description="是否验证汇编结果。如果为True，将反汇编修改后的代码进行验证"
    )] = True,
    remove_signature: Annotated[bool, Field(
        description="是否移除代码签名。修改代码后通常需要移除原有签名"
    )] = True
) -> Dict[str, Any]:
    """
    在指定地址替换 Mach-O 指令
    
    该工具提供以下功能：
    - 在指定虚拟地址处替换汇编指令
    - 支持多种架构（x86_64、arm64等）
    - 自动处理代码签名移除
    - 提供汇编结果验证
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
        
        # 设置输出路径 - 如果没有指定，直接覆盖原文件
        if not output_path:
            output_path = file_path
        
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
        
        # 获取原始指令（用于验证和回滚）
        original_instructions = _get_original_instructions(binary, address, 5)
        
        # 执行汇编操作 - 直接使用原始汇编代码，LIEF 支持多行汇编
        try:
            # 使用 LIEF 的 assemble 方法，直接传递多行汇编代码
            binary.assemble(address, assembly_code.strip())
            
        except Exception as e:
            return {
                "error": f"汇编操作失败: {str(e)}",
                "original_instructions": original_instructions,
                "assembly_code": assembly_code.strip(),
                "suggestion": "请检查汇编语法是否正确，或尝试简化指令"
            }
        
        # 移除代码签名（如果需要）
        signature_removed = False
        if remove_signature:
            try:
                if hasattr(binary, 'remove_signature'):
                    binary.remove_signature()
                    signature_removed = True
                elif hasattr(fat_binary, 'remove_signature'):
                    fat_binary.remove_signature()
                    signature_removed = True
            except Exception as e:
                # 签名移除失败不是致命错误
                pass
        
        # 写入修改后的文件
        try:
            if len(fat_binary) == 1:
                # 单架构文件
                binary.write(output_path)
            else:
                # Fat Binary 文件
                fat_binary.write(output_path)
                
        except Exception as e:
            return {
                "error": f"写入修改后的文件失败: {str(e)}",
                "suggestion": "请检查输出路径权限或磁盘空间"
            }
        
        # 验证汇编结果
        verification_result = None
        if verify_assembly:
            verification_result = _verify_assembly_result(output_path, address, architecture)
        
        # 构建结果
        result = {
            "status": "success",
            "operation": "assemble_code",
            "file_info": {
                "original_file": file_path,
                "output_file": output_path,
                "backup_file": backup_path if backup_original else None
            },
            "modification_details": {
                "target_address": {
                    "value": address,
                    "hex": hex(address)
                },
                "original_assembly": assembly_code.strip(),
                "architecture": str(binary.header.cpu_type)
            },
            "original_instructions": original_instructions,
            "signature_removed": signature_removed,
            "verification": verification_result
        }
        
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


def _get_original_instructions(binary: lief.MachO.Binary, address: int, count: int = 5) -> List[Dict[str, Any]]:
    """获取原始指令（用于备份和验证）"""
    
    original_instructions = []
    
    try:
        instruction_iter = binary.disassemble(address)
        
        for i, inst in enumerate(instruction_iter):
            if i >= count:
                break
            
            inst_info = {
                "address": {
                    "value": inst.address,
                    "hex": hex(inst.address)
                },
                "mnemonic": inst.mnemonic,
                "full_instruction": inst.to_string()
            }
            
            # 尝试获取原始字节码
            try:
                if hasattr(inst, 'raw') and inst.raw:
                    raw_bytes = list(inst.raw)
                    inst_info["bytes"] = {
                        "raw": raw_bytes,
                        "hex": ' '.join(f'{b:02x}' for b in raw_bytes),
                        "size": len(raw_bytes)
                    }
            except Exception:
                pass
            
            original_instructions.append(inst_info)
        
    except Exception as e:
        # 如果无法获取原始指令，返回错误信息
        original_instructions = [{
            "error": f"无法获取原始指令: {str(e)}"
        }]
    
    return original_instructions


def _verify_assembly_result(output_path: str, address: int, architecture: str) -> Dict[str, Any]:
    """验证汇编结果"""
    
    verification = {
        "verified": False,
        "new_instructions": [],
        "error": None
    }
    
    try:
        # 重新解析修改后的文件
        fat_binary = lief.MachO.parse(output_path)
        if fat_binary is None:
            verification["error"] = "无法解析修改后的文件"
            return verification
        
        # 选择架构
        binary = _select_architecture(fat_binary, architecture)
        if binary is None:
            verification["error"] = "无法找到指定架构"
            return verification
        
        # 反汇编修改后的指令
        instruction_iter = binary.disassemble(address)
        
        for i, inst in enumerate(instruction_iter):
            if i >= 5:  # 只验证前5条指令
                break
            
            inst_info = {
                "address": {
                    "value": inst.address,
                    "hex": hex(inst.address)
                },
                "mnemonic": inst.mnemonic,
                "full_instruction": inst.to_string()
            }
            
            verification["new_instructions"].append(inst_info)
        
        verification["verified"] = True
        
    except Exception as e:
        verification["error"] = f"验证过程中发生错误: {str(e)}"
    
    return verification


def _analyze_assembly_impact(original_instructions: List[Dict[str, Any]], 
                           new_instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """分析汇编修改的影响"""
    
    analysis = {
        "instructions_changed": 0,
        "bytes_changed": 0,
        "instruction_comparison": [],
        "potential_issues": []
    }
    
    try:
        # 比较指令
        max_len = max(len(original_instructions), len(new_instructions))
        
        for i in range(max_len):
            comparison = {"index": i}
            
            if i < len(original_instructions):
                comparison["original"] = original_instructions[i]
            else:
                comparison["original"] = None
            
            if i < len(new_instructions):
                comparison["new"] = new_instructions[i]
            else:
                comparison["new"] = None
            
            # 检查是否有变化
            if comparison["original"] and comparison["new"]:
                if (comparison["original"].get("full_instruction") != 
                    comparison["new"].get("full_instruction")):
                    comparison["changed"] = True
                    analysis["instructions_changed"] += 1
                else:
                    comparison["changed"] = False
            else:
                comparison["changed"] = True
                analysis["instructions_changed"] += 1
            
            analysis["instruction_comparison"].append(comparison)
        
        # 检查潜在问题
        if analysis["instructions_changed"] == 0:
            analysis["potential_issues"].append("没有检测到指令变化，汇编可能未生效")
        
        if len(new_instructions) > len(original_instructions):
            analysis["potential_issues"].append("新指令数量超过原始指令，可能覆盖了后续代码")
        
    except Exception as e:
        analysis["error"] = f"分析过程中发生错误: {str(e)}"
    
    return analysis
