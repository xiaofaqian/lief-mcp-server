"""
将汇编指令转换为字节码的MCP工具
"""
from typing import Dict, Any, List, Annotated, Optional
from pydantic import Field
import re
import keystone


def assemble_to_bytes(
    assembly_instruction: Annotated[str, Field(
        description="要转换的汇编指令，支持地址和符号。例如：'mov x0, #1'、'bl #0x100001000'、'bl my_function'"
    )],
    base_address: Annotated[str, Field(
        description="当前指令的虚拟地址，用于计算相对跳转。默认为 '0x100000000'。支持十六进制格式，例如：'0x100000000'"
    )] = "0x100000000",
    architecture: Annotated[str, Field(
        description="目标架构，支持 'arm64'、'x86'、'x86_64'。默认为 'arm64'"
    )] = "arm64",
    symbol_table: Annotated[Optional[Dict[str, str]], Field(
        description="符号表，键为符号名，值为十六进制地址。例如：{'my_function': '0x100001000'}。如果指令包含符号但未提供符号表，将返回错误"
    )] = None
) -> Dict[str, Any]:
    """
    将汇编指令转换为对应的机器码字节。
    
    此工具使用 Keystone Engine 将汇编指令转换为机器码，支持多种架构
    和符号解析。对于包含相对跳转的指令，需要提供正确的基地址来计算
    偏移量。
    
    功能特性：
    - 支持 ARM64、x86、x86_64 架构
    - 自动检测和解析符号引用
    - 正确处理相对跳转指令的地址计算
    - 提供详细的错误信息和调试信息
    
    返回信息包括：
    - 原始和解析后的汇编指令
    - 十六进制字节码（格式化显示）
    - 原始字节数据（hex字符串）
    - 字节长度和架构信息
    - 使用的符号信息
    """
    try:
        # 验证参数
        if not assembly_instruction or not isinstance(assembly_instruction, str):
            return {
                "success": False,
                "error": "无效的汇编指令参数"
            }
        
        if not base_address:
            return {
                "success": False,
                "error": "基地址参数不能为空"
            }
        
        # 解析基地址
        try:
            if isinstance(base_address, str):
                if base_address.startswith('0x') or base_address.startswith('0X'):
                    base_addr = int(base_address, 16)
                else:
                    base_addr = int(base_address, 10)
            else:
                base_addr = int(base_address)
        except ValueError:
            return {
                "success": False,
                "error": f"无效的基地址格式: {base_address}"
            }
        
        # 获取架构参数
        arch_result = _get_keystone_arch(architecture)
        if not arch_result["success"]:
            return arch_result
        
        # 检测和解析符号
        symbol_result = _detect_and_resolve_symbols(assembly_instruction, symbol_table)
        if not symbol_result["success"]:
            return symbol_result
        
        resolved_instruction = symbol_result["resolved_instruction"]
        symbols_used = symbol_result["symbols_used"]
        
        # 汇编指令
        assemble_result = _assemble_instruction(
            resolved_instruction, 
            base_addr, 
            arch_result["arch_params"]
        )
        if not assemble_result["success"]:
            return assemble_result
        
        # 格式化字节码
        raw_bytes = assemble_result["bytes"]
        hex_bytes = " ".join(f"{b:02x}" for b in raw_bytes)
        raw_hex = "".join(f"{b:02x}" for b in raw_bytes)
        
        result = {
            "success": True,
            "original_instruction": assembly_instruction,
            "base_address": hex(base_addr),
            "architecture": architecture,
            "hex_bytes": hex_bytes,
            "raw_bytes": raw_hex,
            "byte_length": len(raw_bytes)
        }
        
        # 添加符号信息（如果有）
        if symbols_used:
            result["resolved_instruction"] = resolved_instruction
            result["symbols_used"] = symbols_used
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": f"汇编过程中发生错误: {str(e)}"
        }


def _get_keystone_arch(architecture: str) -> Dict[str, Any]:
    """获取 Keystone 引擎的架构参数"""
    try:
        arch_map = {
            "arm64": (keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN),
            "x86": (keystone.KS_ARCH_X86, keystone.KS_MODE_32),
            "x86_64": (keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        }
        
        if architecture.lower() not in arch_map:
            return {
                "success": False,
                "error": f"不支持的架构: {architecture}。支持的架构: {list(arch_map.keys())}"
            }
        
        return {
            "success": True,
            "arch_params": arch_map[architecture.lower()]
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"架构参数获取失败: {str(e)}"
        }


def _detect_and_resolve_symbols(instruction: str, symbol_table: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """检测指令中的符号并解析为地址"""
    try:
        # 符号检测模式
        symbol_patterns = [
            r'bl\s+([a-zA-Z_][a-zA-Z0-9_]*)',           # bl my_function
            r'b\s+([a-zA-Z_][a-zA-Z0-9_]*)',            # b my_label
            r'adrp\s+\w+,\s*([a-zA-Z_][a-zA-Z0-9_]*)', # adrp x0, my_symbol
            r'add\s+\w+,\s*\w+,\s*:lo12:([a-zA-Z_][a-zA-Z0-9_]*)', # add x0, x1, :lo12:my_symbol
        ]
        
        symbols_found = []
        resolved_instruction = instruction
        symbols_used = {}
        
        # 检测所有符号
        for pattern in symbol_patterns:
            matches = re.findall(pattern, instruction)
            symbols_found.extend(matches)
        
        # 如果没有符号，直接返回原指令
        if not symbols_found:
            return {
                "success": True,
                "resolved_instruction": instruction,
                "symbols_used": {}
            }
        
        # 如果有符号但没有符号表，返回错误
        if not symbol_table:
            return {
                "success": False,
                "error": f"指令包含符号 {symbols_found} 但未提供符号表",
                "original_instruction": instruction,
                "symbols_detected": symbols_found
            }
        
        # 解析每个符号
        for symbol in symbols_found:
            if symbol not in symbol_table:
                return {
                    "success": False,
                    "error": f"符号 '{symbol}' 在符号表中未找到",
                    "original_instruction": instruction,
                    "symbols_detected": symbols_found,
                    "available_symbols": list(symbol_table.keys())
                }
            
            # 验证符号地址格式
            symbol_address = symbol_table[symbol]
            try:
                if symbol_address.startswith('0x') or symbol_address.startswith('0X'):
                    addr_value = int(symbol_address, 16)
                else:
                    addr_value = int(symbol_address, 10)
                
                # 将符号替换为地址
                # 处理不同的指令格式
                if f"bl {symbol}" in resolved_instruction:
                    resolved_instruction = resolved_instruction.replace(f"bl {symbol}", f"bl #{symbol_address}")
                elif f"b {symbol}" in resolved_instruction:
                    resolved_instruction = resolved_instruction.replace(f"b {symbol}", f"b #{symbol_address}")
                elif f"adrp " in resolved_instruction and symbol in resolved_instruction:
                    resolved_instruction = resolved_instruction.replace(symbol, symbol_address)
                elif f":lo12:{symbol}" in resolved_instruction:
                    resolved_instruction = resolved_instruction.replace(f":lo12:{symbol}", f":lo12:{symbol_address}")
                
                symbols_used[symbol] = symbol_address
                
            except ValueError:
                return {
                    "success": False,
                    "error": f"符号 '{symbol}' 的地址格式无效: {symbol_address}",
                    "original_instruction": instruction
                }
        
        return {
            "success": True,
            "resolved_instruction": resolved_instruction,
            "symbols_used": symbols_used
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"符号解析失败: {str(e)}"
        }


def _assemble_instruction(instruction: str, base_address: int, arch_params: tuple) -> Dict[str, Any]:
    """使用 Keystone 引擎汇编指令"""
    try:
        # 初始化 Keystone 引擎
        ks = keystone.Ks(arch_params[0], arch_params[1])
        
        # 汇编指令
        encoding, count = ks.asm(instruction, base_address)
        
        if not encoding:
            return {
                "success": False,
                "error": f"汇编失败，可能是无效的指令语法: {instruction}"
            }
        
        return {
            "success": True,
            "bytes": bytes(encoding),
            "instruction_count": count
        }
        
    except keystone.KsError as e:
        return {
            "success": False,
            "error": f"Keystone 汇编错误: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"汇编引擎错误: {str(e)}"
        }
