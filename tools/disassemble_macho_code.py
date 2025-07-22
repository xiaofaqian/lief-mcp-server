"""
Mach-O 代码反汇编工具

此工具专门用于使用 LIEF 反汇编 Mach-O 文件中的代码段，支持多种反汇编方式。
提供按虚拟地址、函数名或节名反汇编代码的功能，支持多种架构的指令分析。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os
import re


def disassemble_macho_code(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    target_type: Annotated[str, Field(
        description="反汇编目标类型：'address'(按地址)、'function'(按函数名)、'section'(按节名)"
    )],
    target_value: Annotated[str, Field(
        description="目标值：地址(如0x100001000)、函数名(如main)或节名(如__text)"
    )],
    architecture: Annotated[str, Field(
        description="指定架构类型，如 'x86_64'、'arm64' 等。如果不指定，将使用默认架构"
    )] = "",
    instruction_count: Annotated[int, Field(
        description="要反汇编的指令数量，默认20条，最大100条。对于函数反汇编，此参数被忽略",
        ge=1,
        le=100
    )] = 20,
    show_bytes: Annotated[bool, Field(
        description="是否显示指令的原始字节码"
    )] = True
) -> Dict[str, Any]:
    """
    使用 LIEF 反汇编 Mach-O 文件中的代码段，支持多种反汇编方式。
    
    该工具提供以下功能：
    - 按虚拟地址反汇编指定数量的指令
    - 按函数名反汇编整个函数的代码
    - 按节名反汇编整个代码节
    - 支持多种架构（x86_64、arm64等）
    - 使用 LIEF 库，提供详细的指令分析
    
    支持单架构和 Fat Binary 文件的代码反汇编。
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
        if target_type not in ["address", "function", "section"]:
            return {
                "error": f"无效的目标类型: {target_type}",
                "suggestion": "请使用 'address'、'function' 或 'section' 中的一个"
            }
        
        if not target_value.strip():
            return {
                "error": "目标值不能为空",
                "suggestion": "请提供有效的地址、函数名或节名"
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
        
        # 根据目标类型进行反汇编
        if target_type == "address":
            result = _disassemble_by_address(binary, target_value, instruction_count, show_bytes)
        elif target_type == "function":
            result = _disassemble_by_function(binary, target_value, show_bytes)
        elif target_type == "section":
            result = _disassemble_by_section(binary, target_value, instruction_count, show_bytes)
        
        return result
        
    except Exception as e:
        return {
            "error": f"反汇编代码时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "target_type": target_type,
            "target_value": target_value,
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


def _disassemble_by_address(binary: lief.MachO.Binary, address_str: str, instruction_count: int, show_bytes: bool) -> Dict[str, Any]:
    """按地址反汇编指定数量的指令"""
    
    try:
        # 解析地址
        if address_str.startswith('0x') or address_str.startswith('0X'):
            address = int(address_str, 16)
        else:
            try:
                address = int(address_str, 16)
            except ValueError:
                address = int(address_str, 10)
        
        # 验证地址是否在有效范围内
        if not _is_valid_address(binary, address):
            return {
                "error": f"地址 {hex(address)} 不在有效的代码段范围内",
                "suggestion": "请检查地址是否正确，或使用 list_macho_segments 工具查看可用的代码段"
            }
        
        # 使用 LIEF 反汇编
        instructions = []
        instruction_iter = binary.disassemble(address)
        
        count = 0
        for inst in instruction_iter:
            if count >= instruction_count:
                break
            
            inst_info = _extract_instruction_info(inst, show_bytes)
            instructions.append(inst_info)
            count += 1
        
        if not instructions:
            return {
                "error": f"无法在地址 {hex(address)} 处反汇编指令",
                "suggestion": "请检查地址是否指向有效的代码，或尝试其他地址"
            }
        
        return {
            "status": "success",
            "instruction_count": len(instructions),
            "instructions": '\n'.join(instructions)
        }
        
    except ValueError as e:
        return {
            "error": f"无效的地址格式: {address_str}",
            "suggestion": "请使用十六进制格式（如 0x100001000）或十进制格式"
        }
    except Exception as e:
        return {
            "error": f"按地址反汇编时发生错误: {str(e)}",
            "suggestion": "请检查地址是否有效，或尝试其他地址"
        }


def _disassemble_by_function(binary: lief.MachO.Binary, function_name: str, show_bytes: bool) -> Dict[str, Any]:
    """按函数名反汇编整个函数的代码"""
    
    try:
        # 查找函数符号
        function_symbol = None
        for symbol in binary.symbols:
            if symbol.name == function_name or symbol.name == f"_{function_name}":
                function_symbol = symbol
                break
        
        if function_symbol is None:
            # 尝试在导出符号中查找
            for export in binary.dyld_info.exports:
                if hasattr(export, 'symbol') and export.symbol:
                    if export.symbol.name == function_name or export.symbol.name == f"_{function_name}":
                        function_symbol = export.symbol
                        break
        
        if function_symbol is None:
            available_functions = _get_available_functions(binary)
            return {
                "error": f"未找到函数: {function_name}",
                "available_functions": available_functions[:20],  # 只显示前20个
                "suggestion": f"请检查函数名是否正确，或查看 available_functions 列表。尝试添加下划线前缀: _{function_name}"
            }
        
        # 获取函数地址
        function_address = function_symbol.value
        
        if function_address == 0:
            return {
                "error": f"函数 {function_name} 的地址为0，可能是外部函数",
                "suggestion": "请尝试反汇编本地定义的函数"
            }
        
        # 验证地址是否在有效范围内
        if not _is_valid_address(binary, function_address):
            return {
                "error": f"函数 {function_name} 的地址 {hex(function_address)} 不在有效的代码段范围内",
                "suggestion": "请检查函数是否为本地定义的函数"
            }
        
        # 反汇编函数
        instructions = []
        instruction_iter = binary.disassemble(function_address)
        
        # 尝试确定函数结束位置
        function_end = _estimate_function_end(binary, function_address)
        
        for inst in instruction_iter:
            inst_info = _extract_instruction_info(inst, show_bytes)
            instructions.append(inst_info)
            
            # 检查是否到达函数结束
            if function_end and inst.address >= function_end:
                break
            
            # 检查是否遇到返回指令
            if _is_return_instruction(inst):
                break
            
            # 防止无限循环
            if len(instructions) > 1000:
                break
        
        if not instructions:
            return {
                "error": f"无法反汇编函数 {function_name}",
                "suggestion": "请检查函数地址是否有效"
            }
        
        return {
            "status": "success",
            "instruction_count": len(instructions),
            "instructions": '\n'.join(instructions)
        }
        
    except Exception as e:
        return {
            "error": f"按函数名反汇编时发生错误: {str(e)}",
            "suggestion": "请检查函数名是否正确"
        }


def _disassemble_by_section(binary: lief.MachO.Binary, section_name: str, instruction_count: int, show_bytes: bool) -> Dict[str, Any]:
    """按节名反汇编整个代码节"""
    
    try:
        # 查找指定的节
        target_section = None
        target_segment = None
        
        for segment in binary.segments:
            for section in segment.sections:
                if section.name == section_name:
                    target_section = section
                    target_segment = segment
                    break
            if target_section:
                break
        
        if target_section is None:
            available_sections = _get_available_code_sections(binary)
            return {
                "error": f"未找到节: {section_name}",
                "available_code_sections": available_sections,
                "suggestion": "请检查节名是否正确，或查看 available_code_sections 列表"
            }
        
        # 检查是否为代码节
        if not _is_code_section(target_section, target_segment):
            return {
                "error": f"节 {section_name} 不是代码节",
                "section_info": {
                    "name": target_section.name,
                    "segment": target_segment.name,
                    "size": target_section.size
                },
                "suggestion": "请选择包含可执行代码的节，如 __text"
            }
        
        # 反汇编节内容
        section_address = target_section.virtual_address
        instructions = []
        instruction_iter = binary.disassemble(section_address)
        
        count = 0
        section_end = section_address + target_section.size
        
        for inst in instruction_iter:
            if count >= instruction_count and instruction_count > 0:
                break
            
            # 检查是否超出节范围
            if inst.address >= section_end:
                break
            
            inst_info = _extract_instruction_info(inst, show_bytes)
            instructions.append(inst_info)
            count += 1
        
        if not instructions:
            return {
                "error": f"无法反汇编节 {section_name}",
                "suggestion": "请检查节是否包含有效的代码"
            }
        
        return {
            "status": "success",
            "instruction_count": len(instructions),
            "instructions": '\n'.join(instructions)
        }
        
    except Exception as e:
        return {
            "error": f"按节名反汇编时发生错误: {str(e)}",
            "suggestion": "请检查节名是否正确"
        }


def _extract_instruction_info(inst, show_bytes: bool) -> str:
    """提取单条指令的简洁信息，返回格式化字符串"""
    
    # 获取操作数信息
    operands_str = ""
    try:
        # 从 to_string() 中提取操作数部分
        full_str = inst.to_string()
        if ':' in full_str:
            parts = full_str.split(':', 1)
            if len(parts) > 1:
                instruction_part = parts[1].strip()
                # 分离助记符和操作数
                inst_parts = instruction_part.split(None, 1)
                if len(inst_parts) > 1:
                    operands_str = inst_parts[1]
    except Exception:
        operands_str = ""
    
    # 格式化地址
    address_hex = f"0x{inst.address:08x}"
    
    # 获取机器指令字节码
    bytes_str = ""
    if show_bytes:
        try:
            if hasattr(inst, 'raw') and inst.raw:
                raw_bytes = list(inst.raw)
                # 按4字节对齐，不足4字节则补零
                bytes_to_show = raw_bytes[:4]
                # 补零到4字节
                while len(bytes_to_show) < 4:
                    bytes_to_show.append(0)
                # 格式化为两个字节一组，中间留空格
                byte_pairs = []
                for i in range(0, len(bytes_to_show), 2):
                    if i + 1 < len(bytes_to_show):
                        byte_pairs.append(f'{bytes_to_show[i]:02x}{bytes_to_show[i+1]:02x}')
                    else:
                        byte_pairs.append(f'{bytes_to_show[i]:02x}00')
                bytes_str = ' '.join(byte_pairs)
            elif hasattr(inst, 'size') and inst.size > 0:
                bytes_str = "N/A"
        except Exception:
            bytes_str = "N/A"
    
    # 组合指令字符串
    if operands_str:
        instruction_str = f"{inst.mnemonic} {operands_str}"
    else:
        instruction_str = inst.mnemonic
    
    # 返回格式化的字符串
    if show_bytes and bytes_str:
        return f"{address_hex} {instruction_str} {bytes_str}"
    else:
        return f"{address_hex} {instruction_str}"




def _is_valid_address(binary: lief.MachO.Binary, address: int) -> bool:
    """检查地址是否在有效的代码段范围内"""
    
    for segment in binary.segments:
        if segment.virtual_address <= address < segment.virtual_address + segment.virtual_size:
            # 检查是否为可执行段
            if hasattr(segment, 'flags') and 'EXECUTE' in str(segment.flags):
                return True
            # 检查段名称
            if segment.name in ['__TEXT']:
                return True
    
    return False


def _is_code_section(section, segment) -> bool:
    """检查是否为代码节"""
    
    # 检查节名称
    if section.name in ['__text', '__stubs', '__stub_helper']:
        return True
    
    # 检查段名称
    if segment.name == '__TEXT':
        return True
    
    # 检查节标志
    if hasattr(section, 'flags'):
        flags_str = str(section.flags)
        if 'SOME_INSTRUCTIONS' in flags_str or 'PURE_INSTRUCTIONS' in flags_str:
            return True
    
    return False


def _is_return_instruction(inst) -> bool:
    """检查是否为返回指令"""
    
    mnemonic = inst.mnemonic.lower()
    return mnemonic in ['ret', 'retq', 'return', 'bx']


def _estimate_function_end(binary: lief.MachO.Binary, function_start: int) -> Optional[int]:
    """估算函数结束地址"""
    
    # 查找下一个函数的开始地址
    next_function_start = None
    
    for symbol in binary.symbols:
        if symbol.value > function_start and symbol.value != 0:
            # 检查是否为函数符号
            if hasattr(symbol, 'type') and 'SECTION' in str(symbol.type):
                if next_function_start is None or symbol.value < next_function_start:
                    next_function_start = symbol.value
    
    return next_function_start


def _get_available_functions(binary: lief.MachO.Binary) -> List[str]:
    """获取可用的函数列表"""
    
    functions = []
    
    for symbol in binary.symbols:
        if symbol.value != 0 and hasattr(symbol, 'type') and 'SECTION' in str(symbol.type):
            functions.append(symbol.name)
    
    return sorted(list(set(functions)))


def _get_available_code_sections(binary: lief.MachO.Binary) -> List[Dict[str, str]]:
    """获取可用的代码节列表"""
    
    code_sections = []
    
    for segment in binary.segments:
        for section in segment.sections:
            if _is_code_section(section, segment):
                code_sections.append({
                    "section_name": section.name,
                    "segment_name": segment.name,
                    "size": f"{section.size} bytes"
                })
    
    return code_sections
