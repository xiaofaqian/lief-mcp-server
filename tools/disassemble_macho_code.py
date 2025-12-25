"""
Mach-O 代码反汇编工具

此工具专门用于使用 LIEF 反汇编 Mach-O 文件中的代码段，支持多种反汇编方式。
提供按虚拟地址、函数名或节名反汇编代码的功能，支持多种架构的指令分析。
"""

from typing import Annotated, Dict, Any, List, Optional, Tuple
from pydantic import Field
import lief

from .common import (
    get_available_architectures,
    is_executable_address,
    parse_macho,
    parse_number,
    select_architecture_by_name,
    validate_file_path,
)


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
    )] = True,
    engine: Annotated[str, Field(
        description="反汇编引擎：'auto'(优先capstone)、'lief' 或 'capstone'"
    )] = "auto",
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
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error
        
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
        
        fat_binary, parse_error = parse_macho(file_path)
        if parse_error:
            return parse_error
        
        # 选择架构
        binary = select_architecture_by_name(fat_binary, architecture)
        if binary is None:
            available_archs = get_available_architectures(fat_binary)
            return {
                "error": f"未找到指定的架构: {architecture}",
                "available_architectures": available_archs,
                "suggestion": f"请使用可用的架构之一: {', '.join(available_archs)}"
            }
        
        if engine not in ["auto", "lief", "capstone"]:
            return {
                "error": f"无效的反汇编引擎: {engine}",
                "suggestion": "请使用 'auto'、'lief' 或 'capstone'",
            }

        use_capstone = engine in ["auto", "capstone"] and _capstone_available()

        # 根据目标类型进行反汇编
        if target_type == "address":
            result = _disassemble_by_address(binary, target_value, instruction_count, show_bytes, use_capstone)
        elif target_type == "function":
            result = _disassemble_by_function(binary, target_value, show_bytes, use_capstone)
        elif target_type == "section":
            result = _disassemble_by_section(binary, target_value, instruction_count, show_bytes, use_capstone)
        
        return result
        
    except Exception as e:
        return {
            "error": f"反汇编代码时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "target_type": target_type,
            "target_value": target_value,
            "suggestion": "请检查文件格式和参数是否正确，或联系技术支持"
        }


def _disassemble_by_address(
    binary: lief.MachO.Binary,
    address_str: str,
    instruction_count: int,
    show_bytes: bool,
    use_capstone: bool,
) -> Dict[str, Any]:
    """按地址反汇编指定数量的指令"""
    
    try:
        # 解析地址
        address, _, parse_error = parse_number(address_str, "auto", prefer_hex=True)
        if parse_error:
            return {
                "error": f"无效的地址格式: {address_str}",
                "suggestion": "请使用十六进制格式（如 0x100001000）或十进制格式"
            }
        
        # 验证地址是否在有效范围内
        if not is_executable_address(binary, address):
            return {
                "error": f"地址 {hex(address)} 不在有效的代码段范围内",
                "suggestion": "请检查地址是否正确，或使用 list_macho_segments 工具查看可用的代码段"
            }
        
        instructions: List[str] = []
        if use_capstone:
            instructions = _capstone_disassemble(binary, address, None, instruction_count, show_bytes)
        if not instructions:
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


def _disassemble_by_function(
    binary: lief.MachO.Binary,
    function_name: str,
    show_bytes: bool,
    use_capstone: bool,
) -> Dict[str, Any]:
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
        if not is_executable_address(binary, function_address):
            return {
                "error": f"函数 {function_name} 的地址 {hex(function_address)} 不在有效的代码段范围内",
                "suggestion": "请检查函数是否为本地定义的函数"
            }
        
        instructions: List[str] = []
        function_end = _estimate_function_end(binary, function_address)

        if use_capstone:
            size = None
            if function_end and function_end > function_address:
                size = function_end - function_address
            else:
                size = _estimate_read_size(binary, 512)
            instructions = _capstone_disassemble(binary, function_address, size, 0, show_bytes, stop_on_return=True)

        if not instructions:
            instruction_iter = binary.disassemble(function_address)
            for inst in instruction_iter:
                inst_info = _extract_instruction_info(inst, show_bytes)
                instructions.append(inst_info)
                if function_end and inst.address >= function_end:
                    break
                if _is_return_instruction(inst):
                    break
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


def _disassemble_by_section(
    binary: lief.MachO.Binary,
    section_name: str,
    instruction_count: int,
    show_bytes: bool,
    use_capstone: bool,
) -> Dict[str, Any]:
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
        
        section_address = target_section.virtual_address
        section_end = section_address + target_section.size
        instructions: List[str] = []
        if use_capstone:
            instructions = _capstone_disassemble(
                binary,
                section_address,
                target_section.size,
                instruction_count,
                show_bytes,
                stop_on_address=section_end,
            )
        if not instructions:
            instruction_iter = binary.disassemble(section_address)
            count = 0
            for inst in instruction_iter:
                if count >= instruction_count and instruction_count > 0:
                    break
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


def _capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except Exception:
        return False


def _get_capstone_engine(binary: lief.MachO.Binary):
    try:
        import capstone
    except Exception:
        return None

    cpu = str(binary.header.cpu_type).upper()
    if "ARM64" in cpu:
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    if "ARM" in cpu:
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
    if "X86_64" in cpu or "X86_64H" in cpu:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if "X86" in cpu:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return None


def _capstone_disassemble(
    binary: lief.MachO.Binary,
    address: int,
    size: Optional[int],
    instruction_count: int,
    show_bytes: bool,
    stop_on_return: bool = False,
    stop_on_address: Optional[int] = None,
) -> List[str]:
    md = _get_capstone_engine(binary)
    if md is None:
        return []
    if size is None:
        size = _estimate_read_size(binary, instruction_count)
    try:
        data = binary.get_content_from_virtual_address(address, size)
        code = bytes(data)
    except Exception:
        return []

    instructions: List[str] = []
    for inst in md.disasm(code, address):
        if instruction_count and len(instructions) >= instruction_count:
            break
        if stop_on_address and inst.address >= stop_on_address:
            break
        mnemonic = inst.mnemonic.lower()
        if stop_on_return and mnemonic in ["ret", "retq", "bx"]:
            instructions.append(_format_capstone_instruction(inst, show_bytes))
            break
        instructions.append(_format_capstone_instruction(inst, show_bytes))

    return instructions


def _format_capstone_instruction(inst: Any, show_bytes: bool) -> str:
    operands = inst.op_str or ""
    inst_str = f"{inst.mnemonic} {operands}".strip()
    if show_bytes:
        bytes_str = " ".join(f"{b:02x}" for b in inst.bytes)
        return f"{hex(inst.address)} {inst_str} {bytes_str}".strip()
    return f"{hex(inst.address)} {inst_str}".strip()


def _estimate_read_size(binary: lief.MachO.Binary, instruction_count: int) -> int:
    count = max(instruction_count, 1)
    cpu = str(binary.header.cpu_type).upper()
    if "ARM" in cpu:
        return count * 4
    if "X86" in cpu:
        return count * 16
    return count * 8
