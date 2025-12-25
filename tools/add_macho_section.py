"""
为 Mach-O 文件添加新的代码节，使用 LIEF 的简化 API 自动处理地址分配。

该工具提供以下功能：
- 使用 LIEF 的 add_section() 方法自动添加节
- 自动处理地址分配，无需手动计算
- 支持空白填充或 NOP 指令填充
- 自动根据架构选择合适的 NOP 指令
- 支持单架构和 Fat Binary 文件
- 自动处理代码签名移除

支持的架构和 NOP 指令：
- x86_64: 0x90 (NOP)
- ARM64: 0x1F2003D5 (NOP)
- 其他架构: 零字节填充
"""

from typing import Annotated, Dict, Any, Optional
from pydantic import Field
import lief

from .common import format_size, parse_macho, select_architecture_by_index, validate_file_path


def add_macho_section(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    section_name: Annotated[str, Field(
        description="新节的名称，例如：__shell、__code、__inject等。建议使用双下划线开头的格式"
    )] = "__shell",
    size: Annotated[int, Field(
        description="代码段的大小（字节），必须大于0。建议使用4096的倍数以符合内存页对齐",
        gt=0
    )] = 4096,
    fill_type: Annotated[str, Field(
        description="填充类型：'empty'(零字节填充) 或 'nop'(NOP指令填充)。NOP指令会根据架构自动选择"
    )] = "nop",
    architecture_index: Annotated[int, Field(
        description="对于Fat Binary文件，指定要修改的架构索引（从0开始）。如果不指定，将修改第一个架构",
        ge=0
    )] = 0,
    output_path: Annotated[Optional[str], Field(
        description="输出文件的完整绝对路径。如果不指定，将覆盖原文件"
    )] = None
) -> Dict[str, Any]:
    """
    为 Mach-O 文件添加新的代码节，LIEF 会自动处理地址分配和段创建。
    
    该工具提供以下功能：
    - 使用 LIEF 的 add_section() 方法自动添加节
    - 自动处理地址分配，无需手动计算
    - 支持空白填充或 NOP 指令填充
    - 自动根据架构选择合适的 NOP 指令
    - 支持单架构和 Fat Binary 文件
    - 自动处理代码签名移除
    
    支持的架构和 NOP 指令：
    - x86_64: 0x90 (NOP)
    - ARM64: 0x1F2003D5 (NOP)
    - 其他架构: 零字节填充
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error
        
        # 验证参数
        if fill_type not in ["empty", "nop"]:
            return {
                "error": f"无效的填充类型: {fill_type}",
                "suggestion": "填充类型必须是 'empty' 或 'nop'"
            }
        
        fat_binary, parse_error = parse_macho(file_path)
        if parse_error:
            return parse_error
        
        binary, arch_error = select_architecture_by_index(fat_binary, architecture_index)
        if arch_error:
            return arch_error
        
        # 获取架构信息
        arch_info = _get_architecture_info(binary)
        
        # 生成填充内容
        content = _generate_fill_content(fill_type, size, arch_info["cpu_type"])
        
        # 创建新的节，使用官方推荐的简化方式
        section = lief.MachO.Section(section_name, content)
        section.alignment = 2  # 4字节对齐 (2^2)
        
        # 设置节标志为代码节
        try:
            section += lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS
            section += lief.MachO.SECTION_FLAGS.PURE_INSTRUCTIONS
        except Exception as e:
            # 如果设置标志失败，继续执行但记录警告
            pass
        
        # 记录原始段数量
        original_segments_count = len(binary.segments)
        
        # 直接添加节，LIEF 会自动处理地址分配和段创建
        added_section = binary.add_section(section)
        
        if added_section is None:
            return {
                "error": "添加代码段失败",
                "suggestion": "可能是由于段名称冲突或其他内部错误"
            }
        
        # 移除代码签名（如果存在）
        try:
            binary.remove_signature()
        except Exception as e:
            # 如果没有签名或移除失败，继续执行
            pass
        
        # 确定输出路径
        final_output_path = output_path if output_path else file_path
        
        # 写入修改后的文件
        if len(fat_binary) == 1:
            # 单架构文件，直接写入
            binary.write(final_output_path)
        else:
            # Fat Binary，需要写入整个 fat_binary
            fat_binary.write(final_output_path)
        
        # 构建成功响应
        result = {
            "success": True,
            "file_path": file_path,
            "output_path": final_output_path,
            "is_fat_binary": len(fat_binary) > 1,
            "architecture_count": len(fat_binary),
            "modified_architecture": {
                "index": architecture_index,
                "cpu_type": arch_info["cpu_type"],
                "cpu_subtype": arch_info["cpu_subtype"]
            },
            "section_info": {
                "section_name": section_name,
                "size": size,
                "size_formatted": format_size(size),
                "fill_type": fill_type,
                "virtual_address": hex(added_section.virtual_address) if hasattr(added_section, 'virtual_address') else "N/A",
                "file_offset": hex(added_section.offset) if hasattr(added_section, 'offset') else "N/A",
                "alignment": added_section.alignment if hasattr(added_section, 'alignment') else "N/A"
            },
            "statistics": {
                "original_segments": original_segments_count,
                "new_segments": len(binary.segments),
                "bytes_added": size,
                "content_preview": _get_content_preview(content)
            }
        }
        
        # 添加填充类型特定信息
        if fill_type == "nop":
            result["nop_info"] = _get_nop_info(arch_info["cpu_type"])
        
        return result
        
    except Exception as e:
        return {
            "error": f"添加代码段时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _get_architecture_info(binary: lief.MachO.Binary) -> Dict[str, str]:
    """获取架构信息"""
    try:
        header = binary.header
        return {
            "cpu_type": str(header.cpu_type),
            "cpu_subtype": str(header.cpu_subtype)
        }
    except Exception:
        return {
            "cpu_type": "unknown",
            "cpu_subtype": "unknown"
        }


def _generate_fill_content(fill_type: str, size: int, cpu_type: str) -> list:
    """生成填充内容"""
    if fill_type == "empty":
        return [0x00] * size
    
    elif fill_type == "nop":
        # 根据架构选择 NOP 指令
        if "X86_64" in cpu_type or "I386" in cpu_type:
            # x86/x86_64 NOP 指令
            nop_byte = 0x90
            return [nop_byte] * size
        
        elif "ARM64" in cpu_type or "ARM" in cpu_type:
            # ARM64 NOP 指令: 0x1F2003D5 (little-endian)
            nop_instruction = [0xD5, 0x03, 0x20, 0x1F]
            content = []
            for i in range(size // 4):
                content.extend(nop_instruction)
            # 处理不能被4整除的剩余字节
            remaining = size % 4
            if remaining > 0:
                content.extend([0x00] * remaining)
            return content
        
        else:
            # 未知架构，使用零字节
            return [0x00] * size
    
    else:
        # 默认使用零字节
        return [0x00] * size


def _get_nop_info(cpu_type: str) -> Dict[str, Any]:
    """获取 NOP 指令信息"""
    if "X86_64" in cpu_type or "I386" in cpu_type:
        return {
            "architecture": "x86/x86_64",
            "nop_instruction": "0x90",
            "instruction_size": 1,
            "description": "单字节 NOP 指令"
        }
    elif "ARM64" in cpu_type or "ARM" in cpu_type:
        return {
            "architecture": "ARM64",
            "nop_instruction": "0x1F2003D5",
            "instruction_size": 4,
            "description": "4字节 NOP 指令 (hint #0)"
        }
    else:
        return {
            "architecture": "unknown",
            "nop_instruction": "0x00",
            "instruction_size": 1,
            "description": "使用零字节作为后备填充"
        }


def _get_content_preview(content: list) -> Dict[str, Any]:
    """获取内容预览"""
    preview_size = min(16, len(content))
    preview_bytes = content[:preview_size]
    
    return {
        "first_16_bytes": [hex(b) for b in preview_bytes],
        "total_size": len(content),
        "is_all_same": len(set(content)) == 1,
        "unique_bytes": len(set(content))
    }


def _format_size(size_bytes: int) -> str:
    """兼容旧接口，保留内部调用入口"""
    return format_size(size_bytes)
