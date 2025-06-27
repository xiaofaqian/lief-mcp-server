"""
获取二进制文件头信息的MCP工具
"""
from typing import Dict, Any, Annotated
from pydantic import Field
import lief


def get_binary_header(
    file_path: Annotated[str, Field(
        description="二进制文件在系统中的完整绝对路径，例如：/Users/username/Documents/binary_file 或 /home/user/app/executable，支持ELF、PE、MachO格式的可执行文件"
    )]
) -> Dict[str, Any]:
    """
    获取二进制文件的头信息，支持ELF、PE、MachO格式。
    
    此工具解析二进制文件的头部结构，提取关键信息如架构类型、
    入口点地址、文件类型等。支持跨平台的可执行文件格式分析。
    
    返回的信息根据文件格式而异：
    - ELF: 包含机器架构、入口点、程序头信息等
    - PE: 包含机器类型、子系统、入口点等  
    - MachO: 包含CPU类型、文件类型、加载命令等
    """
    try:
        # 验证文件路径
        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "error": "无效的文件路径参数"
            }
        
        # 解析二进制文件
        binary = lief.parse(file_path)
        if binary is None:
            return {
                "success": False,
                "error": "无法解析文件，可能不是有效的二进制文件或格式不支持"
            }
        
        # 构建基础头信息
        header_info = {
            "success": True,
            "file_path": file_path,
            "format": binary.format.name,
            "entry_point": hex(binary.entrypoint)
        }
        
        # 根据格式添加特定头信息
        if binary.format == lief.Binary.FORMATS.ELF:
            header_info.update(_extract_elf_header(binary))
        elif binary.format == lief.Binary.FORMATS.PE:
            header_info.update(_extract_pe_header(binary))
        elif binary.format == lief.Binary.FORMATS.MACHO:
            header_info.update(_extract_macho_header(binary))
        
        return header_info
        
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
            "error": f"解析头信息时发生错误: {str(e)}"
        }


def _extract_elf_header(binary) -> Dict[str, Any]:
    """提取ELF格式的头信息"""
    try:
        return {
            "architecture": binary.header.machine.name,
            "file_type": binary.header.file_type.name,
            "class": binary.header.identity_class.name,
            "data_encoding": binary.header.identity_data.name,
            "version": binary.header.identity_version.name,
            "program_header_offset": binary.header.program_header_offset,
            "section_header_offset": binary.header.section_header_offset,
            "number_of_sections": binary.header.numberof_sections
        }
    except Exception as e:
        return {"elf_header_error": str(e)}


def _extract_pe_header(binary) -> Dict[str, Any]:
    """提取PE格式的头信息"""
    try:
        return {
            "architecture": binary.header.machine.name,
            "number_of_sections": binary.header.numberof_sections,
            "timestamp": binary.header.time_date_stamps,
            "subsystem": binary.optional_header.subsystem.name,
            "image_base": hex(binary.optional_header.imagebase),
            "section_alignment": binary.optional_header.section_alignment,
            "file_alignment": binary.optional_header.file_alignment
        }
    except Exception as e:
        return {"pe_header_error": str(e)}


def _extract_macho_header(binary) -> Dict[str, Any]:
    """提取MachO格式的头信息"""
    try:
        return {
            "cpu_type": binary.header.cpu_type.name,
            "file_type": binary.header.file_type.name,
            "number_of_commands": binary.header.nb_cmds,
            "size_of_commands": binary.header.sizeof_cmds,
            "flags": [flag.name for flag in binary.header.flags_list]
        }
    except Exception as e:
        return {"macho_header_error": str(e)}
