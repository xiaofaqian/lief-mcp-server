"""
ARM64 分支目标地址计算工具

此工具专门用于计算 ARM64 分支指令的目标地址，支持多种指令类型和输入格式。
提供精确的地址计算功能，适用于逆向工程和二进制分析场景。
"""

from typing import Annotated, Dict, Any, Union
from pydantic import Field

from .common import parse_number


def calculate_arm64_branch_target(
    current_address: Annotated[str, Field(
        description="当前指令的地址，支持十六进制格式（如0x100007008）或十进制格式（如4295000072）"
    )],
    offset: Annotated[str, Field(
        description="跳转偏移量，支持十进制格式（如494872、-494916）或十六进制格式（如0x78E08、-0x78E44）"
    )],
    input_format: Annotated[str, Field(
        description="输入格式：'auto'(自动检测)、'hex'(十六进制)、'dec'(十进制)。默认为'auto'"
    )] = "auto",
    instruction_type: Annotated[str, Field(
        description="指令类型：'bl'(Branch with Link)、'b'(Branch)、'adr'(Address)、'adrp'(Address Page)、'bl_raw'(原始bl偏移×4)、'b_raw'(原始b偏移×4)、'custom'(自定义)。默认为'bl'"
    )] = "bl",
    custom_multiplier: Annotated[int, Field(
        description="自定义偏移量倍数，仅在instruction_type='custom'时使用。默认为4",
        ge=1
    )] = 4
) -> Dict[str, Any]:
    """
    计算 ARM64 分支指令的目标地址
    
    该工具提供以下功能：
    - 支持多种 ARM64 分支指令类型（bl、b、adr等）
    - 自动检测输入格式（十六进制、十进制）
    - 处理正负偏移量
    - 提供详细的计算过程和公式
    - 支持自定义偏移量倍数
    - 完整的错误处理和参数验证
    
    适用于逆向工程、二进制分析和汇编代码理解。
    """
    try:
        # 验证参数
        if not current_address.strip():
            return {
                "error": "当前地址不能为空",
                "suggestion": "请提供有效的地址，如 0x100007008 或 4295000072"
            }
        
        if not offset.strip():
            return {
                "error": "偏移量不能为空", 
                "suggestion": "请提供有效的偏移量，如 494872 或 -494916"
            }
        
        if input_format not in ["auto", "hex", "dec"]:
            return {
                "error": f"无效的输入格式: {input_format}",
                "suggestion": "请使用 'auto'、'hex' 或 'dec' 中的一个"
            }
        
        if instruction_type not in ["bl", "b", "adr", "adrp", "bl_raw", "b_raw", "custom"]:
            return {
                "error": f"无效的指令类型: {instruction_type}",
                "suggestion": "请使用 'bl'、'b'、'adr'、'adrp'、'bl_raw'、'b_raw' 或 'custom' 中的一个"
            }
        
        current_addr_value, current_format, parse_error = parse_number(current_address.strip(), input_format)
        if parse_error:
            return {
                "error": f"解析当前地址失败: {parse_error['error']}",
                "input_address": current_address,
                "suggestion": "请检查地址格式，支持十六进制（0x100007008）或十进制（4295000072）"
            }
        
        offset_value, offset_format, offset_error = parse_number(offset.strip(), input_format)
        if offset_error:
            return {
                "error": f"解析偏移量失败: {offset_error['error']}",
                "input_offset": offset,
                "suggestion": "请检查偏移量格式，支持十六进制（0x78E08）或十进制（494872），可以为负数"
            }
        
        # 根据指令类型计算目标地址
        if instruction_type == "adrp":
            # ADRP: 目标地址 = (PC & ~0xFFF) + 立即数
            # 立即数已经是页面偏移量，不需要额外处理
            page_aligned_pc = current_addr_value & ~0xFFF
            target_address = page_aligned_pc + offset_value
            multiplier = 1  # 用于显示目的
            byte_offset = offset_value
        else:
            # 其他指令类型使用原有逻辑
            multiplier = _get_instruction_multiplier(instruction_type, custom_multiplier)
            byte_offset = offset_value * multiplier
            target_address = current_addr_value + byte_offset
        
        # 确保目标地址为正数
        if target_address < 0:
            return {
                "error": f"计算得到的目标地址为负数: {target_address}",
                "calculation_details": {
                    "current_address": current_addr_value,
                    "offset": offset_value,
                    "multiplier": multiplier,
                    "byte_offset": byte_offset
                },
                "suggestion": "请检查偏移量是否过大或当前地址是否正确"
            }
        
        # 构建详细结果
        result = {
            "status": "success",
            "calculation_details": {
                "current_address": {
                    "value": current_addr_value,
                    "hex": hex(current_addr_value),
                    "input_format": current_format,
                    "original_input": current_address
                },
                "offset": {
                    "value": offset_value,
                    "hex": hex(offset_value) if offset_value >= 0 else f"-{hex(-offset_value)}",
                    "input_format": offset_format,
                    "original_input": offset,
                    "is_negative": offset_value < 0
                },
                "instruction_info": {
                    "type": instruction_type,
                    "multiplier": multiplier,
                    "description": _get_instruction_description(instruction_type)
                }
            },
            "target_address": {
                "value": target_address,
                "hex": hex(target_address)
            },
            "calculation_process": _get_calculation_process(
                instruction_type, current_addr_value, offset_value, multiplier, 
                byte_offset, target_address
            ),
            "analysis": {
                "byte_offset": byte_offset,
                "direction": "backward" if offset_value < 0 else "forward",
                "distance": abs(byte_offset),
                "address_range": {
                    "start": min(current_addr_value, target_address),
                    "end": max(current_addr_value, target_address),
                    "span": abs(byte_offset)
                }
            }
        }
        
        # 添加指令特定的分析
        if instruction_type in ["bl", "b"]:
            result["instruction_analysis"] = _analyze_branch_instruction(
                current_addr_value, target_address, instruction_type
            )
        elif instruction_type == "adr":
            result["instruction_analysis"] = _analyze_adr_instruction(
                current_addr_value, target_address
            )
        elif instruction_type == "adrp":
            result["instruction_analysis"] = _analyze_adrp_instruction(
                current_addr_value, target_address, offset_value
            )
        
        return result
        
    except Exception as e:
        return {
            "error": f"计算分支目标地址时发生未预期的错误: {str(e)}",
            "input_parameters": {
                "current_address": current_address,
                "offset": offset,
                "input_format": input_format,
                "instruction_type": instruction_type,
                "custom_multiplier": custom_multiplier
            },
            "suggestion": "请检查输入参数是否正确，或联系技术支持"
        }


def _get_instruction_multiplier(instruction_type: str, custom_multiplier: int) -> int:
    """获取指令的偏移量倍数"""
    
    multipliers = {
        "bl": 1,    # Branch with Link，反汇编器显示的偏移量通常已经是字节偏移量
        "b": 1,     # Branch，反汇编器显示的偏移量通常已经是字节偏移量
        "adr": 1,   # Address，偏移量以字节为单位
        "bl_raw": 4,    # 原始指令编码中的bl偏移量，需要乘以4
        "b_raw": 4,     # 原始指令编码中的b偏移量，需要乘以4
        "custom": custom_multiplier
    }
    
    return multipliers.get(instruction_type, 1)


def _get_instruction_description(instruction_type: str) -> str:
    """获取指令类型的描述"""
    
    descriptions = {
        "bl": "Branch with Link - 带链接的分支指令，用于函数调用",
        "b": "Branch - 无条件分支指令，用于跳转",
        "adr": "Address - 地址计算指令，计算相对地址",
        "adrp": "Address Page - 页面地址计算指令，计算4KB页面对齐的地址",
        "custom": "Custom - 自定义指令类型"
    }
    
    return descriptions.get(instruction_type, "未知指令类型")


def _get_calculation_process(instruction_type: str, current_addr: int, offset_value: int, 
                           multiplier: int, byte_offset: int, target_address: int) -> Dict[str, Any]:
    """获取计算过程的详细信息"""
    
    if instruction_type == "adrp":
        page_aligned_pc = current_addr & ~0xFFF
        return {
            "formula": f"({hex(current_addr)} & ~0xFFF) + {offset_value} = {hex(target_address)}",
            "step_by_step": [
                f"当前地址: {hex(current_addr)}",
                f"页面对齐地址: {hex(current_addr)} & ~0xFFF = {hex(page_aligned_pc)}",
                f"立即数(页面偏移): {offset_value} (0x{offset_value:x})",
                f"目标地址: {hex(page_aligned_pc)} + {offset_value} = {hex(target_address)}",
                f"页面数: {offset_value // 4096} 页面 (验证: {offset_value} ÷ 4096)"
            ]
        }
    else:
        return {
            "formula": f"{hex(current_addr)} + ({offset_value} × {multiplier}) = {hex(target_address)}",
            "step_by_step": [
                f"当前地址: {hex(current_addr)}",
                f"偏移量: {offset_value} ({'负向' if offset_value < 0 else '正向'})",
                f"指令倍数: {multiplier} ({'字节' if multiplier == 1 else '字(4字节)' if multiplier == 4 else f'{multiplier}字节'})",
                f"字节偏移: {offset_value} × {multiplier} = {byte_offset}",
                f"目标地址: {hex(current_addr)} + {byte_offset} = {hex(target_address)}"
            ]
        }


def _analyze_adrp_instruction(current_addr: int, target_addr: int, imm_value: int) -> Dict[str, Any]:
    """分析 ADRP 指令的特性"""
    
    page_aligned_pc = current_addr & ~0xFFF
    page_count = imm_value // 4096
    
    analysis = {
        "instruction_type": "adrp",
        "page_aligned_pc": page_aligned_pc,
        "immediate_value": imm_value,
        "page_count": page_count,
        "target_alignment": target_addr % 4096 == 0,
        "likely_purpose": "计算页面对齐的地址，通常用于访问全局变量或函数指针"
    }
    
    # 分析页面偏移
    if page_count == 0:
        analysis["page_description"] = "同一页面内"
    elif page_count > 0:
        analysis["page_description"] = f"向前 {page_count} 个页面"
    else:
        analysis["page_description"] = f"向后 {abs(page_count)} 个页面"
    
    # 分析地址范围
    distance = abs(target_addr - page_aligned_pc)
    if distance < 1024 * 1024:  # 1MB
        analysis["distance_category"] = "near"
        analysis["distance_description"] = f"近距离访问 ({distance // 1024}KB)"
    elif distance < 1024 * 1024 * 1024:  # 1GB
        analysis["distance_category"] = "medium"
        analysis["distance_description"] = f"中距离访问 ({distance // (1024 * 1024)}MB)"
    else:
        analysis["distance_category"] = "far"
        analysis["distance_description"] = f"远距离访问 ({distance // (1024 * 1024 * 1024)}GB)"
    
    # 验证计算
    analysis["calculation_verification"] = {
        "page_aligned_pc_hex": hex(page_aligned_pc),
        "immediate_hex": hex(imm_value),
        "target_hex": hex(target_addr),
        "formula_check": f"({hex(current_addr)} & ~0xFFF) + 0x{imm_value:x} = {hex(target_addr)}"
    }
    
    return analysis


def _analyze_branch_instruction(current_addr: int, target_addr: int, instruction_type: str) -> Dict[str, Any]:
    """分析分支指令的特性"""
    
    analysis = {
        "instruction_type": instruction_type,
        "jump_distance": abs(target_addr - current_addr),
        "jump_direction": "backward" if target_addr < current_addr else "forward",
        "is_function_call": instruction_type == "bl",
        "address_alignment": {
            "current_aligned": current_addr % 4 == 0,
            "target_aligned": target_addr % 4 == 0
        }
    }
    
    # 分析跳转距离
    distance = analysis["jump_distance"]
    if distance < 1024:
        analysis["distance_category"] = "short_jump"
        analysis["distance_description"] = "短距离跳转（< 1KB）"
    elif distance < 1024 * 1024:
        analysis["distance_category"] = "medium_jump"
        analysis["distance_description"] = f"中距离跳转（{distance // 1024}KB）"
    else:
        analysis["distance_category"] = "long_jump"
        analysis["distance_description"] = f"长距离跳转（{distance // (1024 * 1024)}MB）"
    
    # 分析可能的用途
    if instruction_type == "bl":
        if analysis["jump_direction"] == "forward":
            analysis["likely_purpose"] = "调用后续定义的函数"
        else:
            analysis["likely_purpose"] = "调用前面定义的函数或库函数"
    else:  # b
        if analysis["jump_direction"] == "backward":
            analysis["likely_purpose"] = "循环跳转或错误处理"
        else:
            analysis["likely_purpose"] = "条件跳转或程序流程控制"
    
    return analysis


def _analyze_adr_instruction(current_addr: int, target_addr: int) -> Dict[str, Any]:
    """分析 ADR 指令的特性"""
    
    analysis = {
        "instruction_type": "adr",
        "address_offset": target_addr - current_addr,
        "target_alignment": target_addr % 4 == 0,
        "likely_purpose": "计算数据地址或跳转表地址"
    }
    
    # 分析偏移量范围
    offset = analysis["address_offset"]
    if -4096 <= offset <= 4095:
        analysis["offset_range"] = "adr_range"
        analysis["range_description"] = "在 ADR 指令的有效范围内（±4KB）"
    else:
        analysis["offset_range"] = "adrp_range"
        analysis["range_description"] = "超出 ADR 范围，可能需要使用 ADRP 指令"
    
    return analysis
