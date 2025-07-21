"""
地址偏移计算工具

此工具用于计算两个地址之间的偏移量，支持多种输入和输出格式。
提供精确的地址偏移计算功能，适用于二进制分析和逆向工程场景。
"""

from typing import Annotated, Dict, Any
from pydantic import Field
import re


def calculate_address_offset(
    current_address: Annotated[str, Field(
        description="当前地址，支持十六进制格式（如0x100001000）或十进制格式（如4295000072）"
    )],
    target_address: Annotated[str, Field(
        description="目标地址，支持十六进制格式（如0x100007008）或十进制格式（如4295024648）"
    )],
    input_format: Annotated[str, Field(
        description="输入格式：'auto'(自动检测)、'hex'(十六进制)、'dec'(十进制)。默认为'auto'"
    )] = "auto",
    output_format: Annotated[str, Field(
        description="输出格式：'all'(所有格式)、'hex'(十六进制)、'dec'(十进制)、'signed_dec'(有符号十进制)。默认为'all'"
    )] = "all"
) -> Dict[str, Any]:
    """
    计算两个地址之间的偏移量
    
    该工具提供以下功能：
    - 支持多种地址输入格式（十六进制、十进制）
    - 自动检测输入格式
    - 计算正负偏移量（目标地址 - 当前地址）
    - 提供多种输出格式
    - 完整的错误处理和参数验证
    - 显示详细的计算过程和分析
    
    适用于二进制分析、逆向工程和汇编代码分析。
    """
    
    try:
        # 验证参数
        if not current_address.strip():
            return {
                "error": "当前地址不能为空",
                "suggestion": "请提供有效的地址，如 0x100001000 或 4295000072"
            }
        
        if not target_address.strip():
            return {
                "error": "目标地址不能为空",
                "suggestion": "请提供有效的地址，如 0x100007008 或 4295024648"
            }
        
        if input_format not in ["auto", "hex", "dec"]:
            return {
                "error": f"无效的输入格式: {input_format}",
                "suggestion": "请使用 'auto'、'hex' 或 'dec' 中的一个"
            }
        
        if output_format not in ["all", "hex", "dec", "signed_dec"]:
            return {
                "error": f"无效的输出格式: {output_format}",
                "suggestion": "请使用 'all'、'hex'、'dec' 或 'signed_dec' 中的一个"
            }
        
        # 解析当前地址
        current_addr_result = _parse_address(current_address.strip(), input_format)
        if "error" in current_addr_result:
            return {
                "error": f"解析当前地址失败: {current_addr_result['error']}",
                "input_address": current_address,
                "suggestion": "请检查地址格式，支持十六进制（0x100001000）或十进制（4295000072）"
            }
        
        # 解析目标地址
        target_addr_result = _parse_address(target_address.strip(), input_format)
        if "error" in target_addr_result:
            return {
                "error": f"解析目标地址失败: {target_addr_result['error']}",
                "input_address": target_address,
                "suggestion": "请检查地址格式，支持十六进制（0x100007008）或十进制（4295024648）"
            }
        
        # 计算偏移量
        current_addr_value = current_addr_result["value"]
        target_addr_value = target_addr_result["value"]
        offset = target_addr_value - current_addr_value
        
        # 构建详细结果
        result = {
            "status": "success",
            "calculation_details": {
                "current_address": {
                    "value": current_addr_value,
                    "hex": hex(current_addr_value),
                    "input_format": current_addr_result["detected_format"],
                    "original_input": current_address
                },
                "target_address": {
                    "value": target_addr_value,
                    "hex": hex(target_addr_value),
                    "input_format": target_addr_result["detected_format"],
                    "original_input": target_address
                }
            },
            "offset": {
                "value": offset,
                "hex": hex(offset) if offset >= 0 else f"-{hex(-offset)}",
                "signed_decimal": offset,
                "absolute_value": abs(offset),
                "absolute_hex": hex(abs(offset))
            },
            "calculation_process": {
                "formula": f"{hex(target_addr_value)} - {hex(current_addr_value)} = {offset}",
                "step_by_step": [
                    f"目标地址: {hex(target_addr_value)}",
                    f"当前地址: {hex(current_addr_value)}",
                    f"偏移量: {target_addr_value} - {current_addr_value} = {offset}",
                    f"偏移量(十六进制): {hex(offset) if offset >= 0 else f'-{hex(-offset)}'}"
                ]
            },
            "analysis": {
                "direction": "forward" if offset >= 0 else "backward",
                "distance": abs(offset),
                "is_positive": offset >= 0,
                "is_negative": offset < 0,
                "byte_distance": abs(offset)
            }
        }
        
        # 添加对齐分析
        if abs(offset) % 4 == 0:
            result["analysis"]["instruction_aligned"] = True
            result["analysis"]["instruction_count"] = abs(offset) // 4
            result["analysis"]["alignment_note"] = "偏移量是4字节对齐的，适合指令跳转"
        else:
            result["analysis"]["instruction_aligned"] = False
            result["analysis"]["alignment_note"] = "偏移量不是4字节对齐的"
        
        # 添加范围分析
        abs_offset = abs(offset)
        if abs_offset <= 0xFF:
            result["analysis"]["range"] = "8-bit"
            result["analysis"]["range_description"] = "8位范围内（≤255字节）"
        elif abs_offset <= 0xFFFF:
            result["analysis"]["range"] = "16-bit"
            result["analysis"]["range_description"] = "16位范围内（≤64KB）"
        elif abs_offset <= 0xFFFFFFFF:
            result["analysis"]["range"] = "32-bit"
            result["analysis"]["range_description"] = "32位范围内（≤4GB）"
        else:
            result["analysis"]["range"] = "64-bit"
            result["analysis"]["range_description"] = "64位范围内"
        
        # 添加距离分析
        if abs_offset < 1024:
            result["analysis"]["distance_category"] = "short"
            result["analysis"]["distance_description"] = f"短距离（{abs_offset}字节）"
        elif abs_offset < 1024 * 1024:
            result["analysis"]["distance_category"] = "medium"
            result["analysis"]["distance_description"] = f"中距离（{abs_offset // 1024}KB）"
        else:
            result["analysis"]["distance_category"] = "long"
            result["analysis"]["distance_description"] = f"长距离（{abs_offset // (1024 * 1024)}MB）"
        
        # 根据输出格式过滤结果
        if output_format != "all":
            if output_format == "hex":
                result["offset"] = {"hex": hex(offset) if offset >= 0 else f"-{hex(-offset)}"}
            elif output_format == "dec":
                result["offset"] = {"absolute_value": abs(offset)}
            elif output_format == "signed_dec":
                result["offset"] = {"signed_decimal": offset}
        
        return result
        
    except Exception as e:
        return {
            "error": f"计算地址偏移时发生未预期的错误: {str(e)}",
            "input_parameters": {
                "current_address": current_address,
                "target_address": target_address,
                "input_format": input_format,
                "output_format": output_format
            },
            "suggestion": "请检查输入参数是否正确，或联系技术支持"
        }


def _parse_address(address_str: str, format_hint: str) -> Dict[str, Any]:
    """解析地址字符串"""
    
    try:
        # 检测格式
        detected_format = _detect_number_format(address_str)
        
        # 如果指定了格式，使用指定格式，否则使用检测到的格式
        if format_hint != "auto":
            detected_format = format_hint
        
        # 解析地址
        if detected_format == "hex":
            # 处理十六进制
            clean_addr = address_str.lower().replace('0x', '').replace('0X', '')
            if not re.match(r'^[0-9a-f]+$', clean_addr):
                return {"error": f"无效的十六进制地址: {address_str}"}
            value = int(clean_addr, 16)
        else:
            # 处理十进制
            if not re.match(r'^[0-9]+$', address_str):
                return {"error": f"无效的十进制地址: {address_str}"}
            value = int(address_str, 10)
        
        if value < 0:
            return {"error": "地址不能为负数"}
        
        return {
            "value": value,
            "detected_format": detected_format
        }
        
    except ValueError as e:
        return {"error": f"地址解析错误: {str(e)}"}
    except Exception as e:
        return {"error": f"地址解析时发生未知错误: {str(e)}"}


def _detect_number_format(number_str: str) -> str:
    """检测数字格式"""
    
    # 检查是否有十六进制前缀
    if number_str.lower().startswith('0x'):
        return "hex"
    
    # 检查是否包含十六进制字符
    if re.search(r'[a-fA-F]', number_str):
        return "hex"
    
    # 默认为十进制
    return "dec"
