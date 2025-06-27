"""
在指定地址反汇编Mach-O文件的MCP工具
"""
from typing import Dict, Any, List, Annotated
from pydantic import Field
import lief
import capstone


def disassemble_macho_at_address(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /Users/username/Documents/app.app/Contents/MacOS/app"
    )],
    virtual_address: Annotated[str, Field(
        description="要反汇编的虚拟地址（IDA中显示的地址），支持十六进制格式，例如：'0x100001000' 或 '0x1000'"
    )],
    instruction_count: Annotated[int, Field(
        description="要显示的汇编指令数量，默认为10条指令"
    )] = 10,
    show_bytes: Annotated[bool, Field(
        description="是否显示每条指令对应的二进制编码字节，默认为True"
    )] = True
) -> Dict[str, Any]:
    """
    在指定虚拟地址处反汇编Mach-O文件，返回汇编指令和对应的二进制编码。
    
    此工具专门用于分析ARM64架构的Mach-O文件，支持从IDA Pro等反汇编工具
    中复制的虚拟地址直接使用。工具会自动处理地址转换，将虚拟地址转换为
    文件偏移，然后提取对应的机器码进行反汇编。
    
    返回信息包括：
    - 每条指令的地址、助记符、操作数
    - 指令对应的二进制编码（可选）
    - 指令长度和总字节数
    - 地址转换信息
    
    支持的地址格式：
    - 十六进制：0x100001000, 0x1000
    - 十进制：268439552, 4096
    """
    try:
        # 验证参数
        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "error": "无效的文件路径参数"
            }
        
        if not virtual_address:
            return {
                "success": False,
                "error": "虚拟地址参数不能为空"
            }
        
        if instruction_count <= 0:
            return {
                "success": False,
                "error": "指令数量必须大于0"
            }
        
        # 解析虚拟地址
        try:
            if isinstance(virtual_address, str):
                if virtual_address.startswith('0x') or virtual_address.startswith('0X'):
                    va = int(virtual_address, 16)
                else:
                    va = int(virtual_address, 10)
            else:
                va = int(virtual_address)
        except ValueError:
            return {
                "success": False,
                "error": f"无效的地址格式: {virtual_address}"
            }
        
        # 解析Mach-O文件
        binary = lief.parse(file_path)
        if binary is None:
            return {
                "success": False,
                "error": "无法解析文件，可能不是有效的Mach-O文件"
            }
        
        # 确保是Mach-O格式
        if binary.format != lief.Binary.FORMATS.MACHO:
            return {
                "success": False,
                "error": f"文件格式不支持，需要Mach-O格式，当前格式: {binary.format.name}"
            }
        
        # 处理FAT二进制文件
        if hasattr(binary, 'at') and callable(binary.at):
            binary = binary.at(0)
        
        # 获取地址转换信息
        address_info = _get_address_conversion_info(binary, va)
        if not address_info["success"]:
            return address_info
        
        # 读取文件数据
        file_offset = address_info["file_offset"]
        max_bytes = instruction_count * 4  # ARM64指令最大4字节，预估需要的字节数
        
        try:
            with open(file_path, 'rb') as f:
                f.seek(file_offset)
                code_bytes = f.read(max_bytes * 2)  # 读取更多字节以确保足够
        except Exception as e:
            return {
                "success": False,
                "error": f"读取文件数据失败: {str(e)}"
            }
        
        if not code_bytes:
            return {
                "success": False,
                "error": "无法读取指定地址的数据"
            }
        
        # 反汇编
        disasm_result = _disassemble_arm64(code_bytes, va, instruction_count, show_bytes)
        if not disasm_result["success"]:
            return disasm_result
        
        return {
            "success": True,
            "file_path": file_path,
            "virtual_address": hex(va),
            "instruction_count": len(disasm_result["instructions"]),
            "address_info": address_info,
            "instructions": disasm_result["instructions"],
            "total_bytes": disasm_result["total_bytes"]
        }
        
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"文件不存在: {file_path}"
        }
    except PermissionError:
        return {
            "success": False,
            "error": f"没有权限访问文件: {file_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"反汇编过程中发生错误: {str(e)}"
        }


def _get_address_conversion_info(binary, virtual_address: int) -> Dict[str, Any]:
    """获取地址转换信息，将虚拟地址转换为文件偏移"""
    try:
        # 查找包含该地址的段
        target_segment = None
        for segment in binary.segments:
            if segment.virtual_address <= virtual_address < (segment.virtual_address + segment.virtual_size):
                target_segment = segment
                break
        
        if target_segment is None:
            return {
                "success": False,
                "error": f"地址 {hex(virtual_address)} 不在任何有效段中"
            }
        
        # 计算文件偏移
        rva = virtual_address - target_segment.virtual_address
        file_offset = target_segment.file_offset + rva
        
        # 验证是否在可执行段中
        is_executable = hasattr(target_segment, 'flags') and (target_segment.flags & 0x4) != 0
        
        return {
            "success": True,
            "segment_name": target_segment.name,
            "segment_virtual_address": hex(target_segment.virtual_address),
            "segment_file_offset": target_segment.file_offset,
            "relative_virtual_address": hex(rva),
            "file_offset": file_offset,
            "is_executable": is_executable,
            "segment_size": target_segment.virtual_size
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"地址转换失败: {str(e)}"
        }


def _disassemble_arm64(code_bytes: bytes, start_address: int, instruction_count: int, show_bytes: bool) -> Dict[str, Any]:
    """使用Capstone反汇编ARM64代码"""
    try:
        # 初始化Capstone反汇编引擎
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True  # 启用详细信息
        
        instructions = []
        current_address = start_address
        bytes_processed = 0
        
        # 反汇编指令
        for i, instruction in enumerate(md.disasm(code_bytes, start_address)):
            if i >= instruction_count:
                break
            
            # 构建指令信息
            instr_info = {
                "address": hex(instruction.address),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
                "size": instruction.size,
                "instruction": f"{instruction.mnemonic} {instruction.op_str}".strip()
            }
            
            # 添加二进制编码
            if show_bytes:
                instr_bytes = code_bytes[bytes_processed:bytes_processed + instruction.size]
                instr_info["bytes"] = " ".join(f"{b:02x}" for b in instr_bytes)
                instr_info["bytes_raw"] = instr_bytes.hex()
            
            instructions.append(instr_info)
            bytes_processed += instruction.size
            current_address += instruction.size
        
        if not instructions:
            return {
                "success": False,
                "error": "无法反汇编任何指令，可能不是有效的ARM64代码"
            }
        
        return {
            "success": True,
            "instructions": instructions,
            "total_bytes": bytes_processed
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Capstone反汇编失败: {str(e)}"
        }
