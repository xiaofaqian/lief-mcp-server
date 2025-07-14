"""
Mach-O 节内容获取工具

此工具专门用于获取 Mach-O 文件中指定节的原始内容数据，支持以多种格式展示节内容，
包括十六进制、ASCII文本、反汇编代码等。提供灵活的内容查看和分析功能。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os
import binascii


def get_macho_section_content(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    section_name: Annotated[str, Field(
        description="要获取内容的节名称，例如：__text、__data、__cstring、__const等"
    )],
    segment_name: Annotated[Optional[str], Field(
        description="节所属的段名称，例如：__TEXT、__DATA等。如果不指定，将在所有段中搜索匹配的节名称",
        default=None
    )],
    architecture_index: Annotated[Optional[int], Field(
        description="对于Fat Binary文件，指定要分析的架构索引（从0开始）。如果不指定，将分析第一个架构",
        default=0
    )],
    max_bytes: Annotated[Optional[int], Field(
        description="最大读取字节数，用于限制大节的输出。默认为4096字节，设置为0表示读取全部内容",
        default=4096
    )],
    output_format: Annotated[Optional[str], Field(
        description="输出格式：'hex'(十六进制)、'ascii'(ASCII文本)、'raw'(原始字节)、'auto'(自动检测)。默认为'auto'",
        default="auto"
    )]
) -> Dict[str, Any]:
    """
    获取 Mach-O 文件中指定节的内容数据。
    
    该工具提供以下功能：
    - 精确定位指定的节
    - 读取节的原始二进制内容
    - 支持多种输出格式（十六进制、ASCII、原始字节）
    - 自动检测内容类型并选择合适的显示格式
    - 支持内容长度限制，避免输出过大
    - 提供内容统计和分析信息
    
    支持单架构和 Fat Binary 文件的节内容提取。
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
        if not section_name:
            return {
                "error": "节名称不能为空",
                "suggestion": "请提供有效的节名称，例如：__text、__data、__cstring等"
            }
        
        # 解析 Mach-O 文件
        fat_binary = lief.MachO.parse(file_path)
        
        if fat_binary is None:
            return {
                "error": "无法解析文件，可能不是有效的 Mach-O 文件",
                "file_path": file_path,
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        # 检查架构索引
        if architecture_index >= len(fat_binary):
            return {
                "error": f"架构索引 {architecture_index} 超出范围，文件只有 {len(fat_binary)} 个架构",
                "available_architectures": len(fat_binary),
                "suggestion": f"请使用0到{len(fat_binary)-1}之间的架构索引"
            }
        
        # 获取指定架构
        binary = fat_binary[architecture_index]
        
        # 查找指定的节
        target_section = _find_section(binary, section_name, segment_name)
        
        if target_section is None:
            return {
                "error": f"未找到节 '{section_name}'" + (f" 在段 '{segment_name}'" if segment_name else ""),
                "file_path": file_path,
                "architecture_index": architecture_index,
                "available_sections": _list_available_sections(binary),
                "suggestion": "请检查节名称是否正确，或查看available_sections列表中的可用节"
            }
        
        section_obj, found_segment_name = target_section
        
        # 获取节内容
        content_result = _extract_section_content(
            section_obj, 
            found_segment_name, 
            max_bytes, 
            output_format
        )
        
        # 构建完整结果
        result = {
            "file_path": file_path,
            "architecture_index": architecture_index,
            "architecture_info": {
                "cpu_type": str(binary.header.cpu_type),
                "cpu_subtype": str(binary.header.cpu_subtype)
            },
            "section_info": {
                "name": section_obj.name,
                "segment_name": found_segment_name,
                "virtual_address": {
                    "value": section_obj.virtual_address,
                    "hex": hex(section_obj.virtual_address)
                },
                "size": {
                    "value": section_obj.size,
                    "hex": hex(section_obj.size),
                    "human_readable": _format_size(section_obj.size)
                },
                "offset": {
                    "value": section_obj.offset,
                    "hex": hex(section_obj.offset)
                }
            },
            "content": content_result
        }
        
        return result
        
    except Exception as e:
        return {
            "error": f"获取节内容时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "section_name": section_name,
            "suggestion": "请检查文件格式和参数是否正确，或联系技术支持"
        }


def _find_section(binary: lief.MachO.Binary, section_name: str, segment_name: Optional[str]) -> Optional[tuple]:
    """查找指定的节，返回(section, segment_name)元组"""
    
    for segment in binary.segments:
        try:
            for section in segment.sections:
                if section.name == section_name:
                    # 如果指定了段名称，检查是否匹配
                    if segment_name is None or segment.name == segment_name:
                        return (section, segment.name)
        except Exception:
            # 跳过有问题的段
            continue
    
    return None


def _list_available_sections(binary: lief.MachO.Binary) -> List[Dict[str, str]]:
    """列出所有可用的节"""
    
    sections = []
    for segment in binary.segments:
        try:
            for section in segment.sections:
                sections.append({
                    "section_name": section.name,
                    "segment_name": segment.name,
                    "size": _format_size(section.size)
                })
        except Exception:
            continue
    
    return sections


def _extract_section_content(
    section, 
    segment_name: str, 
    max_bytes: int, 
    output_format: str
) -> Dict[str, Any]:
    """提取节的内容数据"""
    
    try:
        # 获取原始内容
        raw_content = section.content
        
        if not raw_content:
            return {
                "status": "empty",
                "message": "节内容为空或无法读取",
                "size": 0
            }
        
        # 将memoryview转换为bytes
        if isinstance(raw_content, memoryview):
            raw_content = raw_content.tobytes()
        elif not isinstance(raw_content, bytes):
            raw_content = bytes(raw_content)
        
        # 应用字节数限制
        original_size = len(raw_content)
        if max_bytes > 0 and original_size > max_bytes:
            raw_content = raw_content[:max_bytes]
            truncated = True
        else:
            truncated = False
        
        # 内容分析
        content_analysis = _analyze_content(raw_content, section.name, segment_name)
        
        # 根据输出格式处理内容
        if output_format == "auto":
            output_format = content_analysis["recommended_format"]
        
        formatted_content = _format_content(raw_content, output_format, content_analysis)
        
        return {
            "status": "success",
            "original_size": original_size,
            "displayed_size": len(raw_content),
            "truncated": truncated,
            "output_format": output_format,
            "content_analysis": content_analysis,
            "formatted_content": formatted_content,
            "raw_preview": {
                "first_16_bytes_hex": binascii.hexlify(raw_content[:16]).decode('ascii') if len(raw_content) >= 16 else binascii.hexlify(raw_content).decode('ascii'),
                "last_16_bytes_hex": binascii.hexlify(raw_content[-16:]).decode('ascii') if len(raw_content) >= 16 else None
            }
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"读取节内容时发生错误: {str(e)}",
            "error_details": str(e)
        }


def _analyze_content(content: bytes, section_name: str, segment_name: str) -> Dict[str, Any]:
    """分析内容类型和特征"""
    
    analysis = {
        "size": len(content),
        "is_empty": len(content) == 0,
        "has_null_bytes": b'\x00' in content,
        "null_byte_ratio": content.count(0) / len(content) if content else 0,
        "printable_ratio": 0,
        "likely_text": False,
        "likely_code": False,
        "likely_data": False,
        "recommended_format": "hex"
    }
    
    if not content:
        return analysis
    
    # 计算可打印字符比例
    printable_count = sum(1 for b in content if 32 <= b <= 126 or b in [9, 10, 13])
    analysis["printable_ratio"] = printable_count / len(content)
    
    # 基于节名称和内容特征判断类型
    if section_name in ["__text", "__stubs", "__stub_helper"]:
        analysis["likely_code"] = True
        analysis["recommended_format"] = "hex"
    elif section_name in ["__cstring", "__const"] and analysis["printable_ratio"] > 0.8:
        analysis["likely_text"] = True
        analysis["recommended_format"] = "ascii"
    elif section_name in ["__data", "__bss", "__common"]:
        analysis["likely_data"] = True
        analysis["recommended_format"] = "hex"
    elif analysis["printable_ratio"] > 0.9 and analysis["null_byte_ratio"] < 0.1:
        analysis["likely_text"] = True
        analysis["recommended_format"] = "ascii"
    else:
        analysis["likely_data"] = True
        analysis["recommended_format"] = "hex"
    
    # 检测特殊模式
    patterns = _detect_patterns(content)
    analysis["detected_patterns"] = patterns
    
    return analysis


def _detect_patterns(content: bytes) -> List[Dict[str, Any]]:
    """检测内容中的特殊模式"""
    
    patterns = []
    
    # 检测字符串模式
    if b'\x00' in content:
        strings = content.split(b'\x00')
        valid_strings = [s for s in strings if len(s) > 3 and all(32 <= b <= 126 for b in s)]
        if valid_strings:
            patterns.append({
                "type": "null_terminated_strings",
                "count": len(valid_strings),
                "examples": [s.decode('ascii', errors='ignore')[:50] for s in valid_strings[:3]]
            })
    
    # 检测重复模式
    if len(content) >= 4:
        # 检查是否有重复的4字节模式
        chunk_size = 4
        chunks = [content[i:i+chunk_size] for i in range(0, len(content), chunk_size)]
        unique_chunks = set(chunks)
        if len(unique_chunks) < len(chunks) * 0.8:  # 如果重复率高
            patterns.append({
                "type": "repetitive_pattern",
                "unique_chunks": len(unique_chunks),
                "total_chunks": len(chunks),
                "repetition_ratio": 1 - (len(unique_chunks) / len(chunks))
            })
    
    # 检测可能的指针或地址
    if len(content) % 8 == 0 and len(content) >= 8:
        # 检查是否像指针数组
        pointer_like = 0
        for i in range(0, len(content), 8):
            chunk = content[i:i+8]
            if len(chunk) == 8:
                value = int.from_bytes(chunk, byteorder='little')
                # 检查是否像有效的内存地址
                if 0x100000000 <= value <= 0x7fffffffffff:  # 64位地址范围
                    pointer_like += 1
        
        if pointer_like > len(content) // 8 * 0.5:  # 超过一半像指针
            patterns.append({
                "type": "pointer_array",
                "potential_pointers": pointer_like,
                "total_entries": len(content) // 8
            })
    
    return patterns


def _format_content(content: bytes, output_format: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
    """根据指定格式格式化内容"""
    
    formatted = {
        "format": output_format,
        "size": len(content)
    }
    
    if output_format == "hex":
        # 十六进制格式，每行16字节
        hex_lines = []
        for i in range(0, len(content), 16):
            chunk = content[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append({
                "offset": f"{i:08x}",
                "hex": hex_part.ljust(47),  # 16*3-1 = 47
                "ascii": ascii_part
            })
        
        formatted["hex_dump"] = hex_lines
        formatted["raw_hex"] = binascii.hexlify(content).decode('ascii')
        
    elif output_format == "ascii":
        # ASCII文本格式
        try:
            text_content = content.decode('utf-8', errors='replace')
            formatted["text"] = text_content
            formatted["lines"] = text_content.split('\n')
            
            # 如果包含null字节，也显示分割的字符串
            if b'\x00' in content:
                strings = content.split(b'\x00')
                valid_strings = [s.decode('utf-8', errors='ignore') for s in strings if s]
                formatted["null_separated_strings"] = valid_strings
                
        except Exception as e:
            formatted["error"] = f"无法解码为文本: {str(e)}"
            formatted["fallback_hex"] = binascii.hexlify(content[:100]).decode('ascii')
    
    elif output_format == "raw":
        # 原始字节格式
        formatted["bytes"] = list(content)
        formatted["hex_representation"] = binascii.hexlify(content).decode('ascii')
        
        # 提供一些统计信息
        byte_counts = {}
        for b in content:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        # 最常见的字节
        most_common = sorted(byte_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        formatted["byte_statistics"] = {
            "unique_bytes": len(byte_counts),
            "most_common_bytes": [{"byte": b, "count": c, "hex": f"0x{b:02x}"} for b, c in most_common]
        }
    
    return formatted


def _format_size(size_bytes: int) -> str:
    """格式化字节大小为人类可读格式"""
    
    if size_bytes == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    unit_index = 0
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.2f} {units[unit_index]}"
