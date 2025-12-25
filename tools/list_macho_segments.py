"""
Mach-O 段信息列表工具

此工具专门用于列出 Mach-O 文件中的所有段（Segment）信息，包括段名称、虚拟地址、文件偏移、大小、权限等详细信息。
提供完整的段结构解析，帮助理解二进制文件的内存布局和段组织结构。
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief

from .common import format_size, parse_macho, validate_file_path


def list_macho_segments(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )]
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有段信息，包括段名称、地址、大小、权限等详细数据。
    
    该工具解析 Mach-O 文件的段结构，提供：
    - 段名称和完整路径
    - 虚拟内存地址和大小
    - 文件偏移和文件大小
    - 段权限和保护属性
    - 段中包含的节（Section）统计
    - 段类型和特殊属性
    
    支持单架构和 Fat Binary 文件的段信息提取。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error
        
        fat_binary, parse_error = parse_macho(file_path)
        if parse_error:
            return parse_error
        
        # 构建结果
        result = {
            "file_path": file_path,
            "is_fat_binary": len(fat_binary) > 1,
            "architecture_count": len(fat_binary),
            "architectures": []
        }
        
        # 遍历所有架构的段信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_segments = _extract_segments_info(binary, i)
                result["architectures"].append(arch_segments)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 段信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件段信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_segments_info(binary: lief.MachO.Binary, index: int) -> Dict[str, Any]:
    """提取单个架构的段详细信息"""
    
    header = binary.header
    segments = binary.segments
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "segments_count": len(segments),
        "segments": []
    }
    
    # 遍历所有段
    for segment in segments:
        try:
            segment_info = _extract_single_segment_info(segment)
            arch_info["segments"].append(segment_info)
        except Exception as e:
            arch_info["segments"].append({
                "name": getattr(segment, 'name', 'unknown'),
                "error": f"解析段信息时发生错误: {str(e)}"
            })
    
    # 添加段统计信息
    arch_info["segment_statistics"] = _calculate_segment_statistics(arch_info["segments"])
    
    return arch_info


def _extract_single_segment_info(segment) -> Dict[str, Any]:
    """提取单个段的详细信息"""
    
    segment_info = {
        "name": segment.name,
        "virtual_address": {
            "value": segment.virtual_address,
            "hex": hex(segment.virtual_address)
        },
        "virtual_size": {
            "value": segment.virtual_size,
            "hex": hex(segment.virtual_size),
            "human_readable": format_size(segment.virtual_size)
        },
        "file_offset": {
            "value": segment.file_offset,
            "hex": hex(segment.file_offset)
        },
        "file_size": {
            "value": segment.file_size,
            "hex": hex(segment.file_size),
            "human_readable": format_size(segment.file_size)
        },
        "max_protection": {
            "value": segment.max_protection,
            "hex": hex(segment.max_protection),
            "flags": _parse_protection_flags(segment.max_protection),
            "description": _get_protection_description(segment.max_protection)
        },
        "init_protection": {
            "value": segment.init_protection,
            "hex": hex(segment.init_protection),
            "flags": _parse_protection_flags(segment.init_protection),
            "description": _get_protection_description(segment.init_protection)
        },
        "sections_count": len(segment.sections),
        "flags": {
            "value": segment.flags,
            "hex": hex(segment.flags),
            "parsed_flags": _parse_segment_flags(segment.flags)
        }
    }
    
    # 添加段的节信息
    if segment.sections:
        segment_info["sections"] = []
        for section in segment.sections:
            try:
                section_info = _extract_section_info(section)
                segment_info["sections"].append(section_info)
            except Exception as e:
                segment_info["sections"].append({
                    "name": getattr(section, 'name', 'unknown'),
                    "error": f"解析节信息时发生错误: {str(e)}"
                })
    
    # 添加段类型分析
    segment_info["segment_analysis"] = _analyze_segment_type(segment.name)
    
    return segment_info


def _extract_section_info(section) -> Dict[str, Any]:
    """提取节的基本信息"""
    
    # 安全地处理标志位
    try:
        flags_value = int(section.flags) if hasattr(section, 'flags') else 0
        flags_hex = hex(flags_value)
    except (TypeError, ValueError):
        # 如果flags是枚举对象，使用字符串表示
        flags_value = str(section.flags) if hasattr(section, 'flags') else "unknown"
        flags_hex = "N/A"
    
    return {
        "name": section.name,
        "segment_name": section.segment_name,
        "virtual_address": {
            "value": section.virtual_address,
            "hex": hex(section.virtual_address)
        },
        "size": {
            "value": section.size,
            "hex": hex(section.size),
            "human_readable": format_size(section.size)
        },
        "offset": {
            "value": section.offset,
            "hex": hex(section.offset)
        },
        "alignment": section.alignment,
        "flags": {
            "value": flags_value,
            "hex": flags_hex,
            "description": str(section.flags) if hasattr(section, 'flags') else "unknown"
        },
        "type": str(section.type) if hasattr(section, 'type') else "unknown"
    }


def _parse_protection_flags(protection: int) -> List[str]:
    """解析保护标志位"""
    flags = []
    
    if protection & 0x1:  # VM_PROT_READ
        flags.append("READ")
    if protection & 0x2:  # VM_PROT_WRITE
        flags.append("WRITE")
    if protection & 0x4:  # VM_PROT_EXECUTE
        flags.append("EXECUTE")
    
    return flags if flags else ["NONE"]


def _get_protection_description(protection: int) -> str:
    """获取保护标志的描述"""
    flags = _parse_protection_flags(protection)
    
    if flags == ["NONE"]:
        return "无权限"
    
    descriptions = {
        "READ": "可读",
        "WRITE": "可写", 
        "EXECUTE": "可执行"
    }
    
    desc_list = [descriptions.get(flag, flag) for flag in flags]
    return " | ".join(desc_list)


def _parse_segment_flags(flags: int) -> List[Dict[str, Any]]:
    """解析段标志位"""
    flag_definitions = [
        (0x1, "SG_HIGHVM", "段占用高虚拟内存地址空间"),
        (0x2, "SG_FVMLIB", "段是固定虚拟内存共享库"),
        (0x4, "SG_NORELOC", "段没有重定位条目"),
        (0x8, "SG_PROTECTED_VERSION_1", "段使用加密保护版本1")
    ]
    
    parsed_flags = []
    for flag_value, flag_name, description in flag_definitions:
        if flags & flag_value:
            parsed_flags.append({
                "flag": flag_name,
                "value": hex(flag_value),
                "description": description
            })
    
    return parsed_flags


def _analyze_segment_type(segment_name: str) -> Dict[str, Any]:
    """分析段类型和用途"""
    
    segment_types = {
        "__PAGEZERO": {
            "type": "空段",
            "purpose": "防止空指针访问的保护段",
            "typical_permissions": "无权限",
            "description": "位于虚拟地址0处，用于捕获空指针解引用"
        },
        "__TEXT": {
            "type": "代码段",
            "purpose": "存储可执行代码和只读数据",
            "typical_permissions": "读取+执行",
            "description": "包含程序的机器代码指令"
        },
        "__DATA": {
            "type": "数据段",
            "purpose": "存储可读写的全局变量和静态数据",
            "typical_permissions": "读取+写入",
            "description": "包含已初始化的全局变量和静态变量"
        },
        "__DATA_CONST": {
            "type": "常量数据段",
            "purpose": "存储只读的常量数据",
            "typical_permissions": "只读",
            "description": "包含常量数据，在运行时不可修改"
        },
        "__DATA_DIRTY": {
            "type": "脏数据段",
            "purpose": "存储需要写时复制的数据",
            "typical_permissions": "读取+写入",
            "description": "包含可能被修改的共享数据"
        },
        "__OBJC": {
            "type": "Objective-C段",
            "purpose": "存储Objective-C运行时数据",
            "typical_permissions": "读取+写入",
            "description": "包含Objective-C类、方法、协议等元数据"
        },
        "__LINKEDIT": {
            "type": "链接编辑段",
            "purpose": "存储动态链接器信息",
            "typical_permissions": "只读",
            "description": "包含符号表、字符串表、重定位信息等"
        },
        "__IMPORT": {
            "type": "导入段",
            "purpose": "存储导入函数的跳转表",
            "typical_permissions": "读取+执行",
            "description": "包含外部函数调用的跳转代码"
        }
    }
    
    # 查找匹配的段类型
    for seg_name, info in segment_types.items():
        if segment_name.startswith(seg_name):
            return info
    
    # 未知段类型
    return {
        "type": "自定义段",
        "purpose": "用户定义或特殊用途段",
        "typical_permissions": "取决于具体用途",
        "description": f"段名称: {segment_name}"
    }


def _calculate_segment_statistics(segments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算段统计信息"""
    
    stats = {
        "total_segments": len(segments),
        "total_virtual_size": 0,
        "total_file_size": 0,
        "segment_types": {},
        "protection_summary": {
            "readable": 0,
            "writable": 0,
            "executable": 0
        },
        "largest_segment": None,
        "smallest_segment": None
    }
    
    largest_size = 0
    smallest_size = float('inf')
    
    for segment in segments:
        if "error" in segment:
            continue
            
        # 累计大小
        if "virtual_size" in segment:
            size = segment["virtual_size"]["value"]
            stats["total_virtual_size"] += size
            
            # 找最大最小段
            if size > largest_size:
                largest_size = size
                stats["largest_segment"] = {
                    "name": segment["name"],
                    "size": segment["virtual_size"]
                }
            
            if size < smallest_size and size > 0:
                smallest_size = size
                stats["smallest_segment"] = {
                    "name": segment["name"],
                    "size": segment["virtual_size"]
                }
        
        if "file_size" in segment:
            stats["total_file_size"] += segment["file_size"]["value"]
        
        # 统计段类型
        if "segment_analysis" in segment:
            seg_type = segment["segment_analysis"]["type"]
            stats["segment_types"][seg_type] = stats["segment_types"].get(seg_type, 0) + 1
        
        # 统计权限
        if "init_protection" in segment:
            flags = segment["init_protection"]["flags"]
            if "READ" in flags:
                stats["protection_summary"]["readable"] += 1
            if "WRITE" in flags:
                stats["protection_summary"]["writable"] += 1
            if "EXECUTE" in flags:
                stats["protection_summary"]["executable"] += 1
    
    # 格式化总大小
    stats["total_virtual_size_formatted"] = format_size(stats["total_virtual_size"])
    stats["total_file_size_formatted"] = format_size(stats["total_file_size"])
    
    return stats


def _format_size(size_bytes: int) -> str:
    """兼容旧接口，保留内部调用入口"""
    return format_size(size_bytes)
