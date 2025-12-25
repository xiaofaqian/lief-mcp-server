"""
ELF 代码反汇编工具
"""

from typing import Annotated, Dict, Any, List, Optional, Tuple
from pydantic import Field
import lief

from .common import parse_number, validate_file_path
from .elf_common import is_executable_address, parse_elf


def disassemble_elf_code(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )],
    target_type: Annotated[str, Field(
        description="反汇编目标类型：'address'(按地址)、'function'(按函数名)、'section'(按节名)"
    )],
    target_value: Annotated[str, Field(
        description="目标值：地址(如0x1000)、函数名(如main)或节名(如.text)"
    )],
    instruction_count: Annotated[int, Field(
        description="要反汇编的指令数量，默认20条，最大100条。对于函数反汇编，此参数被忽略",
        ge=1,
        le=100
    )] = 20,
    show_bytes: Annotated[bool, Field(description="是否显示指令的原始字节码")] = True,
    engine: Annotated[str, Field(
        description="反汇编引擎：'auto'(优先capstone)、'lief' 或 'capstone'"
    )] = "auto",
) -> Dict[str, Any]:
    """
    使用 LIEF 反汇编 ELF 文件中的代码段。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

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

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        if engine not in ["auto", "lief", "capstone"]:
            return {
                "error": f"无效的反汇编引擎: {engine}",
                "suggestion": "请使用 'auto'、'lief' 或 'capstone'",
            }

        use_capstone = engine in ["auto", "capstone"] and _capstone_available()

        if target_type == "address":
            return _disassemble_by_address(elf, target_value, instruction_count, show_bytes, use_capstone)
        if target_type == "function":
            return _disassemble_by_function(elf, target_value, show_bytes, use_capstone)
        return _disassemble_by_section(elf, target_value, instruction_count, show_bytes, use_capstone)

    except Exception as exc:
        return {
            "error": f"反汇编 ELF 代码时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "target_type": target_type,
            "target_value": target_value,
            "suggestion": "请检查文件格式和参数是否正确",
        }


def _disassemble_by_address(
    elf: lief.ELF.Binary,
    address_str: str,
    instruction_count: int,
    show_bytes: bool,
    use_capstone: bool,
) -> Dict[str, Any]:
    address, _, parse_error = parse_number(address_str, "auto", prefer_hex=True)
    if parse_error or address is None:
        return {
            "error": f"无效的地址格式: {address_str}",
            "suggestion": "请使用十六进制格式（如 0x1000）或十进制格式",
        }

    if not is_executable_address(elf, address):
        return {
            "error": f"地址 {hex(address)} 不在可执行段范围内",
            "suggestion": "请检查地址是否正确，或使用 list_elf_segments 工具查看可执行段",
        }

    instructions: List[str] = []
    if use_capstone:
        instructions = _capstone_disassemble(elf, address, None, instruction_count, show_bytes)
    if not instructions:
        for inst in elf.disassemble(address):
            if len(instructions) >= instruction_count:
                break
            instructions.append(_format_instruction(inst, show_bytes))

    if not instructions:
        return {
            "error": f"无法在地址 {hex(address)} 处反汇编指令",
            "suggestion": "请检查地址是否指向有效代码",
        }

    return {
        "status": "success",
        "instruction_count": len(instructions),
        "instructions": "\n".join(instructions),
    }


def _disassemble_by_function(
    elf: lief.ELF.Binary,
    function_name: str,
    show_bytes: bool,
    use_capstone: bool,
) -> Dict[str, Any]:
    symbol = None
    for sym in elf.symbols:
        if sym.name == function_name:
            symbol = sym
            break
    if not symbol:
        return {
            "error": f"未找到函数符号: {function_name}",
            "suggestion": "请确认函数名是否存在于符号表",
        }

    start = symbol.value
    size = symbol.size or 0
    if start == 0:
        return {
            "error": f"函数 {function_name} 地址无效",
            "suggestion": "请确认符号是否包含地址信息",
        }

    instructions: List[str] = []
    if use_capstone and size:
        instructions = _capstone_disassemble(elf, start, size, 0, show_bytes)
    if not instructions:
        for inst in elf.disassemble(start):
            if size and inst.address >= start + size:
                break
            instructions.append(_format_instruction(inst, show_bytes))
            if len(instructions) > 1000:
                break

    if not instructions:
        return {
            "error": f"无法反汇编函数 {function_name}",
            "suggestion": "请检查符号表或尝试按地址反汇编",
        }

    return {
        "status": "success",
        "function": function_name,
        "instruction_count": len(instructions),
        "instructions": "\n".join(instructions),
    }


def _disassemble_by_section(
    elf: lief.ELF.Binary,
    section_name: str,
    instruction_count: int,
    show_bytes: bool,
    use_capstone: bool,
) -> Dict[str, Any]:
    section = None
    for sec in elf.sections:
        if sec.name == section_name:
            section = sec
            break
    if not section:
        return {
            "error": f"未找到节: {section_name}",
            "suggestion": "请确认节名是否正确",
        }

    start = section.virtual_address
    if start == 0:
        return {
            "error": f"节 {section_name} 地址无效",
            "suggestion": "请检查节是否具有有效虚拟地址",
        }

    instructions: List[str] = []
    if use_capstone:
        instructions = _capstone_disassemble(elf, start, section.size, instruction_count, show_bytes)
    if not instructions:
        for inst in elf.disassemble(start):
            if len(instructions) >= instruction_count:
                break
            instructions.append(_format_instruction(inst, show_bytes))

    if not instructions:
        return {
            "error": f"无法反汇编节 {section_name}",
            "suggestion": "请检查节内容是否可执行",
        }

    return {
        "status": "success",
        "section": section_name,
        "instruction_count": len(instructions),
        "instructions": "\n".join(instructions),
    }


def _format_instruction(inst: Any, show_bytes: bool) -> str:
    address_hex = hex(inst.address)
    operands_str = getattr(inst, "op_str", "")
    instruction_str = f"{inst.mnemonic} {operands_str}".strip()
    bytes_str = ""
    if show_bytes:
        try:
            raw_bytes = list(inst.raw)
            bytes_str = " ".join(f"{b:02x}" for b in raw_bytes)
        except Exception:
            bytes_str = "N/A"
    if show_bytes:
        return f"{address_hex} {instruction_str} {bytes_str}".strip()
    return f"{address_hex} {instruction_str}".strip()


def _capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except Exception:
        return False


def _get_capstone_engine(elf: lief.ELF.Binary):
    try:
        import capstone
    except Exception:
        return None

    arch = elf.header.machine_type
    if arch == lief.ELF.ARCH.AARCH64:
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    if arch == lief.ELF.ARCH.ARM:
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
    if arch == lief.ELF.ARCH.X86_64:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if arch == lief.ELF.ARCH.I386:
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return None


def _capstone_disassemble(
    elf: lief.ELF.Binary,
    address: int,
    size: Optional[int],
    instruction_count: int,
    show_bytes: bool,
) -> List[str]:
    md = _get_capstone_engine(elf)
    if md is None:
        return []

    if size is None:
        size = _estimate_read_size(elf, instruction_count)

    try:
        data = elf.get_content_from_virtual_address(address, size)
        code = bytes(data)
    except Exception:
        return []

    instructions: List[str] = []
    for inst in md.disasm(code, address):
        if instruction_count and len(instructions) >= instruction_count:
            break
        bytes_str = ""
        if show_bytes:
            bytes_str = " ".join(f"{b:02x}" for b in inst.bytes)
        operands = inst.op_str or ""
        inst_str = f"{inst.mnemonic} {operands}".strip()
        if show_bytes and bytes_str:
            instructions.append(f"{hex(inst.address)} {inst_str} {bytes_str}".strip())
        else:
            instructions.append(f"{hex(inst.address)} {inst_str}".strip())

    return instructions


def _estimate_read_size(elf: lief.ELF.Binary, instruction_count: int) -> int:
    arch = elf.header.machine_type
    count = max(instruction_count, 1)
    if arch in [lief.ELF.ARCH.AARCH64, lief.ELF.ARCH.ARM]:
        return count * 4
    if arch in [lief.ELF.ARCH.X86_64, lief.ELF.ARCH.I386]:
        return count * 16
    return count * 8
