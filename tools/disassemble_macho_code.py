"""
Mach-O 代码反汇编工具

此工具专门用于反汇编 Mach-O 文件中的代码段，使用 macOS 原生的 otool 工具。
支持按地址、函数名或节名进行反汇编，提供清晰的汇编代码输出。
"""

from typing import Annotated, Dict, Any, List, Optional, Union
from pydantic import Field
import subprocess
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
    使用 otool 反汇编 Mach-O 文件中的代码段，支持多种反汇编方式。
    
    该工具提供以下功能：
    - 按虚拟地址反汇编指定数量的指令
    - 按函数名反汇编整个函数的代码
    - 按节名反汇编整个代码节
    - 支持多种架构（x86_64、arm64等）
    - 使用 macOS 原生 otool 工具，确保兼容性
    
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
                "suggestion": "请使用 'address'、'function' 或 'section' 之一"
            }
        
        if not target_value.strip():
            return {
                "error": "目标值不能为空",
                "suggestion": "请提供有效的地址、函数名或节名"
            }
        
        # 检查 otool 工具是否可用
        if not _check_otool_available():
            return {
                "error": "otool 工具不可用",
                "suggestion": "此工具需要在 macOS 系统上运行，或安装 Xcode Command Line Tools"
            }
        
        # 获取文件架构信息
        arch_info = _get_architecture_info(file_path, architecture)
        if "error" in arch_info:
            return arch_info
        
        # 执行反汇编
        disasm_result = _perform_disassembly(
            file_path, target_type, target_value, instruction_count, 
            show_bytes, arch_info["selected_arch"]
        )
        
        # 构建完整结果
        result = {
            "file_path": file_path,
            "architecture_info": arch_info,
            "disassembly_config": {
                "target_type": target_type,
                "target_value": target_value,
                "instruction_count": instruction_count,
                "show_bytes": show_bytes
            }
        }
        
        result.update(disasm_result)
        return result
        
    except Exception as e:
        return {
            "error": f"反汇编过程中发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "target_type": target_type,
            "target_value": target_value,
            "suggestion": "请检查文件格式和参数是否正确，或联系技术支持"
        }


def _check_otool_available() -> bool:
    """检查 otool 工具是否可用"""
    try:
        result = subprocess.run(['otool', '--version'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _get_architecture_info(file_path: str, requested_arch: str = "") -> Dict[str, Any]:
    """获取文件的架构信息"""
    try:
        # 使用 file 命令获取基本信息
        file_result = subprocess.run(['file', file_path], 
                                   capture_output=True, text=True, timeout=10)
        
        if file_result.returncode != 0:
            return {
                "error": f"无法获取文件信息: {file_result.stderr}",
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        file_output = file_result.stdout.strip()
        
        # 使用 lipo 命令获取架构列表（如果是 Fat Binary）
        lipo_result = subprocess.run(['lipo', '-info', file_path], 
                                   capture_output=True, text=True, timeout=10)
        
        architectures = []
        selected_arch = ""
        
        if lipo_result.returncode == 0:
            lipo_output = lipo_result.stdout.strip()
            
            if "Non-fat file" in lipo_output:
                # 单架构文件
                arch_match = re.search(r'is architecture: (\w+)', lipo_output)
                if arch_match:
                    arch = arch_match.group(1)
                    architectures = [arch]
                    selected_arch = arch
            else:
                # Fat Binary 文件
                arch_match = re.search(r'Architectures in the fat file: .* are: (.+)', lipo_output)
                if arch_match:
                    architectures = arch_match.group(1).split()
                    
                    # 选择架构
                    if requested_arch and requested_arch in architectures:
                        selected_arch = requested_arch
                    else:
                        selected_arch = architectures[0]  # 默认选择第一个
        
        if not architectures:
            return {
                "error": "无法识别文件架构",
                "file_info": file_output,
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        return {
            "file_type": file_output,
            "architectures": architectures,
            "selected_arch": selected_arch,
            "is_fat_binary": len(architectures) > 1
        }
        
    except subprocess.TimeoutExpired:
        return {
            "error": "获取架构信息超时",
            "suggestion": "文件可能过大或系统负载过高，请稍后重试"
        }
    except Exception as e:
        return {
            "error": f"获取架构信息失败: {str(e)}",
            "suggestion": "请检查文件是否为有效的 Mach-O 文件"
        }


def _perform_disassembly(
    file_path: str, 
    target_type: str, 
    target_value: str, 
    instruction_count: int,
    show_bytes: bool,
    architecture: str
) -> Dict[str, Any]:
    """执行实际的反汇编操作"""
    
    try:
        if target_type == "address":
            return _disassemble_by_address(file_path, target_value, instruction_count, show_bytes, architecture)
        elif target_type == "function":
            return _disassemble_by_function(file_path, target_value, instruction_count, show_bytes, architecture)
        elif target_type == "section":
            return _disassemble_by_section(file_path, target_value, instruction_count, show_bytes, architecture)
        else:
            return {"error": f"不支持的目标类型: {target_type}"}
            
    except Exception as e:
        return {
            "error": f"反汇编执行失败: {str(e)}",
            "details": str(e)
        }


def _disassemble_by_address(
    file_path: str, 
    address_str: str, 
    instruction_count: int,
    show_bytes: bool,
    architecture: str
) -> Dict[str, Any]:
    """按地址反汇编"""
    
    try:
        # 解析地址
        if address_str.startswith('0x') or address_str.startswith('0X'):
            address = int(address_str, 16)
            search_pattern = address_str[2:].lower()  # 移除 0x 前缀
        else:
            try:
                address = int(address_str, 16)
                search_pattern = address_str.lower()
            except ValueError:
                address = int(address_str, 10)
                search_pattern = hex(address)[2:]
        
        # 构建 otool 命令
        cmd = ['otool', '-tv', file_path]
        if architecture:
            cmd.extend(['-arch', architecture])
        
        # 执行 otool 命令
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {
                "error": f"otool 执行失败: {result.stderr}",
                "command": ' '.join(cmd),
                "suggestion": "请检查文件格式和架构参数是否正确"
            }
        
        # 解析输出并查找目标地址
        instructions = _parse_otool_output_by_address(
            result.stdout, search_pattern, instruction_count, show_bytes
        )
        
        if not instructions:
            return {
                "error": f"未找到地址 {address_str} 的反汇编代码",
                "suggestion": "请检查地址是否正确，或使用 list_macho_segments 工具查看可用的地址范围"
            }
        
        # 分析反汇编结果
        analysis = _analyze_instructions(instructions)
        
        return {
            "disassembly_type": "address",
            "start_address": address_str,
            "instruction_count": len(instructions),
            "instructions": instructions,
            "analysis": analysis
        }
        
    except ValueError as e:
        return {
            "error": f"无效的地址格式: {address_str}",
            "suggestion": "请使用十六进制格式（如0x100001000）或十进制格式"
        }
    except subprocess.TimeoutExpired:
        return {
            "error": "反汇编操作超时",
            "suggestion": "文件可能过大，请尝试减少指令数量或选择更小的地址范围"
        }
    except Exception as e:
        return {
            "error": f"按地址反汇编失败: {str(e)}",
            "address": address_str
        }


def _disassemble_by_function(
    file_path: str, 
    function_name: str,
    instruction_count: int,
    show_bytes: bool,
    architecture: str
) -> Dict[str, Any]:
    """按函数名反汇编"""
    
    try:
        # 首先使用 nm 命令查找函数地址
        nm_cmd = ['nm', file_path]
        if architecture:
            nm_cmd.extend(['-arch', architecture])
        
        nm_result = subprocess.run(nm_cmd, capture_output=True, text=True, timeout=15)
        
        if nm_result.returncode != 0:
            return {
                "error": f"nm 命令执行失败: {nm_result.stderr}",
                "suggestion": "无法获取符号信息，请检查文件是否包含符号表"
            }
        
        # 查找函数地址
        function_address = None
        for line in nm_result.stdout.split('\n'):
            if function_name in line or f"_{function_name}" in line:
                parts = line.strip().split()
                if len(parts) >= 3 and (parts[2] == function_name or parts[2] == f"_{function_name}"):
                    try:
                        function_address = parts[0]
                        break
                    except (ValueError, IndexError):
                        continue
        
        if function_address is None:
            return {
                "error": f"未找到函数 '{function_name}'",
                "suggestion": "请使用 list_macho_symbols 工具查看可用的函数符号，或检查函数名是否正确"
            }
        
        # 使用找到的地址进行反汇编
        return _disassemble_by_address(file_path, f"0x{function_address}", instruction_count, show_bytes, architecture)
        
    except subprocess.TimeoutExpired:
        return {
            "error": "符号查找操作超时",
            "suggestion": "文件可能过大，请稍后重试"
        }
    except Exception as e:
        return {
            "error": f"按函数反汇编失败: {str(e)}",
            "function_name": function_name
        }


def _disassemble_by_section(
    file_path: str, 
    section_name: str,
    instruction_count: int,
    show_bytes: bool,
    architecture: str
) -> Dict[str, Any]:
    """按节名反汇编"""
    
    try:
        # 对于节名反汇编，我们需要先找到节的信息
        # 使用 otool -l 获取段和节信息
        cmd = ['otool', '-l', file_path]
        if architecture:
            cmd.extend(['-arch', architecture])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode != 0:
            return {
                "error": f"获取节信息失败: {result.stderr}",
                "suggestion": "请检查文件格式是否正确"
            }
        
        # 解析段和节信息
        section_info = _find_section_info(result.stdout, section_name)
        
        if not section_info:
            return {
                "error": f"未找到节 '{section_name}'",
                "suggestion": "请使用 list_macho_sections 工具查看可用的节，或检查节名是否正确"
            }
        
        # 使用 otool -tv 反汇编整个文件，然后过滤出目标节
        disasm_cmd = ['otool', '-tv', file_path]
        if architecture:
            disasm_cmd.extend(['-arch', architecture])
        
        disasm_result = subprocess.run(disasm_cmd, capture_output=True, text=True, timeout=30)
        
        if disasm_result.returncode != 0:
            return {
                "error": f"反汇编失败: {disasm_result.stderr}",
                "suggestion": "请检查文件是否包含可执行代码"
            }
        
        # 解析输出并提取目标节的代码
        instructions = _parse_otool_output_by_section(
            disasm_result.stdout, section_info, instruction_count, show_bytes
        )
        
        if not instructions:
            return {
                "error": f"节 '{section_name}' 中未找到可反汇编的代码",
                "suggestion": "请确认节包含可执行代码，或选择其他代码节如 __text"
            }
        
        # 分析反汇编结果
        analysis = _analyze_instructions(instructions)
        
        return {
            "disassembly_type": "section",
            "section_name": section_name,
            "section_info": section_info,
            "instruction_count": len(instructions),
            "instructions": instructions,
            "analysis": analysis
        }
        
    except subprocess.TimeoutExpired:
        return {
            "error": "节反汇编操作超时",
            "suggestion": "文件可能过大，请尝试减少指令数量"
        }
    except Exception as e:
        return {
            "error": f"按节反汇编失败: {str(e)}",
            "section_name": section_name
        }


def _parse_otool_output_by_address(
    otool_output: str, 
    search_pattern: str, 
    instruction_count: int,
    show_bytes: bool
) -> List[Dict[str, Any]]:
    """解析 otool 输出，按地址查找指令"""
    
    instructions = []
    lines = otool_output.split('\n')
    found_start = False
    count = 0
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # 查找目标地址
        if not found_start:
            if search_pattern in line.lower():
                found_start = True
            else:
                continue
        
        # 解析指令行
        inst_info = _parse_instruction_line(line, show_bytes)
        if inst_info:
            instructions.append(inst_info)
            count += 1
            
            if count >= instruction_count:
                break
    
    return instructions


def _parse_otool_output_by_section(
    otool_output: str, 
    section_info: Dict[str, Any], 
    instruction_count: int,
    show_bytes: bool
) -> List[Dict[str, Any]]:
    """解析 otool 输出，提取指定节的指令"""
    
    instructions = []
    lines = otool_output.split('\n')
    in_target_section = False
    count = 0
    
    section_start = section_info.get('addr', 0)
    section_end = section_start + section_info.get('size', 0)
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # 检查是否进入目标节
        inst_info = _parse_instruction_line(line, show_bytes)
        if inst_info:
            try:
                addr = int(inst_info['address'], 16)
                if section_start <= addr < section_end:
                    in_target_section = True
                    instructions.append(inst_info)
                    count += 1
                    
                    if count >= instruction_count:
                        break
                elif in_target_section:
                    # 已经超出节范围，停止
                    break
            except (ValueError, KeyError):
                continue
    
    return instructions


def _parse_instruction_line(line: str, show_bytes: bool) -> Optional[Dict[str, Any]]:
    """解析单行指令"""
    
    # otool 输出格式：地址\t指令\t操作数
    # 例如：0000000100003974	pushq	%rbp
    # 或者：0000000100003975	movq	%rsp, %rbp
    
    if '\t' not in line:
        return None
    
    parts = line.split('\t')
    if len(parts) < 2:
        return None
    
    try:
        address = parts[0].strip()
        
        # 处理指令部分
        if len(parts) >= 3:
            # 格式：地址\t助记符\t操作数
            mnemonic = parts[1].strip()
            operands = parts[2].strip() if len(parts) > 2 else ""
            instruction_str = f"{mnemonic}\t{operands}" if operands else mnemonic
        else:
            # 格式：地址\t完整指令
            instruction_str = parts[1].strip()
            inst_parts = instruction_str.split(None, 1)
            mnemonic = inst_parts[0] if inst_parts else ""
            operands = inst_parts[1] if len(inst_parts) > 1 else ""
        
        inst_info = {
            "address": f"0x{address}",
            "instruction": instruction_str,
            "mnemonic": mnemonic,
            "operands": operands
        }
        
        # 添加基本的指令分类
        inst_info["instruction_type"] = _classify_instruction_simple(mnemonic)
        
        # 检查分支和调用指令
        inst_info["is_branch"] = _is_branch_instruction(mnemonic)
        inst_info["is_call"] = _is_call_instruction(mnemonic)
        
        return inst_info
        
    except Exception:
        return None


def _find_section_info(otool_l_output: str, section_name: str) -> Optional[Dict[str, Any]]:
    """从 otool -l 输出中查找节信息"""
    
    lines = otool_l_output.split('\n')
    current_segment = None
    in_section = False
    section_info = {}
    
    for line in lines:
        line = line.strip()
        
        if line.startswith('segname'):
            current_segment = line.split()[-1]
        elif line.startswith('sectname'):
            # 检查节名是否匹配
            if section_name in line:
                # 进一步验证是否完全匹配
                parts = line.split()
                if len(parts) >= 2 and parts[1] == section_name:
                    in_section = True
                    section_info['segment'] = current_segment
                    section_info['name'] = section_name
        elif in_section:
            if line.startswith('addr'):
                try:
                    addr_str = line.split()[-1]
                    section_info['addr'] = int(addr_str, 16)
                except (ValueError, IndexError):
                    pass
            elif line.startswith('size'):
                try:
                    size_str = line.split()[-1]
                    section_info['size'] = int(size_str, 16)
                except (ValueError, IndexError):
                    pass
            elif line.startswith('offset'):
                try:
                    offset_str = line.split()[-1]
                    section_info['offset'] = int(offset_str)
                except (ValueError, IndexError):
                    pass
            elif line.startswith('Section') or line.startswith('Load command') or line.startswith('cmd '):
                # 进入下一个节或加载命令，停止解析当前节
                if 'addr' in section_info:
                    break
                else:
                    # 重置状态，继续查找
                    in_section = False
                    section_info = {}
    
    return section_info if 'addr' in section_info else None


def _classify_instruction_simple(mnemonic: str) -> str:
    """简单的指令分类"""
    
    if not mnemonic:
        return "unknown"
    
    mnemonic = mnemonic.lower()
    
    # 分支指令
    if any(branch in mnemonic for branch in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'b', 'bl', 'br', 'ret']):
        return "branch"
    
    # 调用指令
    if any(call in mnemonic for call in ['call', 'bl', 'blr']):
        return "call"
    
    # 数据移动
    if any(move in mnemonic for move in ['mov', 'ldr', 'str', 'ldp', 'stp', 'push', 'pop']):
        return "data_movement"
    
    # 算术运算
    if any(arith in mnemonic for arith in ['add', 'sub', 'mul', 'div', 'inc', 'dec']):
        return "arithmetic"
    
    # 逻辑运算
    if any(logic in mnemonic for logic in ['and', 'or', 'xor', 'not', 'shl', 'shr']):
        return "logical"
    
    # 比较指令
    if any(comp in mnemonic for comp in ['cmp', 'test']):
        return "comparison"
    
    # 系统指令
    if any(sys in mnemonic for sys in ['syscall', 'svc', 'int', 'nop']):
        return "system"
    
    return "other"


def _is_branch_instruction(mnemonic: str) -> bool:
    """检查是否是分支指令"""
    if not mnemonic:
        return False
    
    mnemonic = mnemonic.lower()
    branch_mnemonics = ['jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'ja', 'jb', 'jae', 'jbe',
                       'b', 'beq', 'bne', 'blt', 'bgt', 'ble', 'bge', 'ret', 'retq']
    
    return any(branch in mnemonic for branch in branch_mnemonics)


def _is_call_instruction(mnemonic: str) -> bool:
    """检查是否是调用指令"""
    if not mnemonic:
        return False
    
    mnemonic = mnemonic.lower()
    call_mnemonics = ['call', 'callq', 'bl', 'blr', 'blx']
    
    return any(call in mnemonic for call in call_mnemonics)


def _analyze_instructions(instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """分析指令列表，提供统计和洞察"""
    
    analysis = {
        "total_instructions": len(instructions),
        "instruction_types": {},
        "branch_instructions": 0,
        "call_instructions": 0,
        "unique_addresses": 0,
        "address_range": {},
        "detected_patterns": []
    }
    
    addresses = []
    
    for inst in instructions:
        if "error" in inst:
            continue
        
        # 统计指令类型
        inst_type = inst.get("instruction_type", "unknown")
        analysis["instruction_types"][inst_type] = analysis["instruction_types"].get(inst_type, 0) + 1
        
        # 统计特殊指令
        if inst.get("is_branch", False):
            analysis["branch_instructions"] += 1
        if inst.get("is_call", False):
            analysis["call_instructions"] += 1
        
        # 收集地址信息
        if "address" in inst:
            try:
                addr = int(inst["address"], 16)
                addresses.append(addr)
            except ValueError:
                pass
    
    # 计算地址范围
    if addresses:
        analysis["address_range"] = {
            "start": hex(min(addresses)),
            "end": hex(max(addresses)),
            "span": max(addresses) - min(addresses)
        }
        analysis["unique_addresses"] = len(set(addresses))
    
    return analysis
