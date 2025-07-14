"""
Mach-O 节信息列表工具

此工具专门用于列出 Mach-O 文件中的所有节（Section）信息，包括节名称、所属段、虚拟地址、大小、标志等详细信息。
提供完整的节结构解析，帮助理解二进制文件的内存布局和节组织结构。
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief
import os


def list_macho_sections(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )]
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有节信息，包括节名称、所属段、地址、大小、标志等详细数据。
    
    该工具解析 Mach-O 文件的节结构，提供：
    - 节名称和所属段名称
    - 虚拟内存地址和大小
    - 文件偏移和对齐方式
    - 节类型和标志位
    - 重定位信息统计
    - 节的用途分析
    
    支持单架构和 Fat Binary 文件的节信息提取。
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
        
        # 解析 Mach-O 文件
        fat_binary = lief.MachO.parse(file_path)
        
        if fat_binary is None:
            return {
                "error": "无法解析文件，可能不是有效的 Mach-O 文件",
                "file_path": file_path,
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        # 构建结果
        result = {
            "file_path": file_path,
            "is_fat_binary": len(fat_binary) > 1,
            "architecture_count": len(fat_binary),
            "architectures": []
        }
        
        # 遍历所有架构的节信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_sections = _extract_sections_info(binary, i)
                result["architectures"].append(arch_sections)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 节信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件节信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_sections_info(binary: lief.MachO.Binary, index: int) -> Dict[str, Any]:
    """提取单个架构的节详细信息"""
    
    header = binary.header
    segments = binary.segments
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "total_sections": 0,
        "sections": []
    }
    
    # 遍历所有段中的节
    for segment in segments:
        try:
            for section in segment.sections:
                try:
                    section_info = _extract_single_section_info(section, segment.name)
                    arch_info["sections"].append(section_info)
                    arch_info["total_sections"] += 1
                except Exception as e:
                    arch_info["sections"].append({
                        "name": getattr(section, 'name', 'unknown'),
                        "segment_name": segment.name,
                        "error": f"解析节信息时发生错误: {str(e)}"
                    })
        except Exception as e:
            # 段解析失败时继续处理其他段
            continue
    
    # 添加节统计信息
    arch_info["section_statistics"] = _calculate_section_statistics(arch_info["sections"])
    
    return arch_info


def _extract_single_section_info(section, segment_name: str) -> Dict[str, Any]:
    """提取单个节的详细信息"""
    
    section_info = {
        "name": section.name,
        "segment_name": segment_name,
        "virtual_address": {
            "value": section.virtual_address,
            "hex": hex(section.virtual_address)
        },
        "size": {
            "value": section.size,
            "hex": hex(section.size),
            "human_readable": _format_size(section.size)
        },
        "offset": {
            "value": section.offset,
            "hex": hex(section.offset)
        },
        "alignment": {
            "value": section.alignment,
            "power_of_2": f"2^{section.alignment}" if section.alignment > 0 else "无对齐"
        }
    }
    
    # 安全地处理标志位
    try:
        flags_value = int(section.flags)
        section_info["flags"] = {
            "value": flags_value,
            "hex": hex(flags_value),
            "parsed_flags": _parse_section_flags(flags_value),
            "description": str(section.flags)
        }
    except (TypeError, ValueError):
        # 如果flags是枚举对象，使用字符串表示
        section_info["flags"] = {
            "value": str(section.flags),
            "hex": "N/A",
            "parsed_flags": [],
            "description": str(section.flags)
        }
    
    # 添加节类型信息
    if hasattr(section, 'type'):
        section_info["type"] = {
            "value": str(section.type),
            "description": _get_section_type_description(str(section.type))
        }
    else:
        section_info["type"] = {
            "value": "unknown",
            "description": "未知节类型"
        }
    
    # 添加重定位信息
    if hasattr(section, 'relocations_count'):
        section_info["relocations_count"] = section.relocations_count
    
    # 添加保留字段
    reserved_fields = {}
    for field_name in ['reserved1', 'reserved2', 'reserved3']:
        if hasattr(section, field_name):
            field_value = getattr(section, field_name)
            reserved_fields[field_name] = {
                "value": field_value,
                "hex": hex(field_value) if isinstance(field_value, int) else str(field_value)
            }
    
    if reserved_fields:
        section_info["reserved_fields"] = reserved_fields
    
    # 添加节用途分析
    section_info["section_analysis"] = _analyze_section_purpose(section.name, segment_name)
    
    return section_info


def _parse_section_flags(flags: int) -> List[Dict[str, Any]]:
    """解析节标志位"""
    
    # Mach-O 节标志位定义
    flag_definitions = [
        (0x80000000, "S_ATTR_PURE_INSTRUCTIONS", "节包含纯指令"),
        (0x40000000, "S_ATTR_NO_TOC", "节不包含目录条目"),
        (0x20000000, "S_ATTR_STRIP_STATIC_SYMS", "可以剥离静态符号"),
        (0x10000000, "S_ATTR_NO_DEAD_STRIP", "不能被死代码剥离"),
        (0x08000000, "S_ATTR_LIVE_SUPPORT", "支持实时更新"),
        (0x04000000, "S_ATTR_SELF_MODIFYING_CODE", "自修改代码"),
        (0x02000000, "S_ATTR_DEBUG", "调试节"),
        (0x00000400, "S_ATTR_SOME_INSTRUCTIONS", "包含一些指令"),
        (0x00000200, "S_ATTR_EXT_RELOC", "有外部重定位条目"),
        (0x00000100, "S_ATTR_LOC_RELOC", "有本地重定位条目")
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


def _get_section_type_description(section_type: str) -> str:
    """获取节类型的描述"""
    
    type_descriptions = {
        "S_REGULAR": "常规节，包含数据或代码",
        "S_ZEROFILL": "零填充节，BSS段",
        "S_CSTRING_LITERALS": "C字符串字面量",
        "S_4BYTE_LITERALS": "4字节字面量",
        "S_8BYTE_LITERALS": "8字节字面量",
        "S_LITERAL_POINTERS": "字面量指针",
        "S_NON_LAZY_SYMBOL_POINTERS": "非延迟符号指针",
        "S_LAZY_SYMBOL_POINTERS": "延迟符号指针",
        "S_SYMBOL_STUBS": "符号存根",
        "S_MOD_INIT_FUNC_POINTERS": "模块初始化函数指针",
        "S_MOD_TERM_FUNC_POINTERS": "模块终止函数指针",
        "S_COALESCED": "合并节",
        "S_GB_ZEROFILL": "巨型零填充节",
        "S_INTERPOSING": "插入节",
        "S_16BYTE_LITERALS": "16字节字面量",
        "S_DTRACE_DOF": "DTrace DOF节",
        "S_LAZY_DYLIB_SYMBOL_POINTERS": "延迟动态库符号指针",
        "S_THREAD_LOCAL_REGULAR": "线程本地常规节",
        "S_THREAD_LOCAL_ZEROFILL": "线程本地零填充节",
        "S_THREAD_LOCAL_VARIABLES": "线程本地变量",
        "S_THREAD_LOCAL_VARIABLE_POINTERS": "线程本地变量指针",
        "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS": "线程本地初始化函数指针"
    }
    
    return type_descriptions.get(section_type, f"未知节类型: {section_type}")


def _analyze_section_purpose(section_name: str, segment_name: str) -> Dict[str, Any]:
    """分析节的用途和特性"""
    
    # 常见节的用途分析
    section_purposes = {
        "__text": {
            "purpose": "可执行代码",
            "content": "程序的机器代码指令",
            "typical_segment": "__TEXT",
            "characteristics": ["只读", "可执行", "包含CPU指令"]
        },
        "__stubs": {
            "purpose": "函数存根",
            "content": "外部函数调用的跳转代码",
            "typical_segment": "__TEXT",
            "characteristics": ["只读", "可执行", "动态链接"]
        },
        "__stub_helper": {
            "purpose": "存根辅助代码",
            "content": "延迟绑定的辅助代码",
            "typical_segment": "__TEXT",
            "characteristics": ["只读", "可执行", "延迟加载"]
        },
        "__cstring": {
            "purpose": "C字符串常量",
            "content": "以null结尾的C字符串",
            "typical_segment": "__TEXT",
            "characteristics": ["只读", "字符串字面量"]
        },
        "__const": {
            "purpose": "常量数据",
            "content": "只读常量数据",
            "typical_segment": "__TEXT",
            "characteristics": ["只读", "常量"]
        },
        "__data": {
            "purpose": "已初始化数据",
            "content": "已初始化的全局和静态变量",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "已初始化"]
        },
        "__bss": {
            "purpose": "未初始化数据",
            "content": "未初始化的全局和静态变量",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "零初始化"]
        },
        "__common": {
            "purpose": "公共符号",
            "content": "公共符号数据",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "公共符号"]
        },
        "__la_symbol_ptr": {
            "purpose": "延迟符号指针",
            "content": "延迟绑定的符号指针",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "延迟绑定"]
        },
        "__nl_symbol_ptr": {
            "purpose": "非延迟符号指针",
            "content": "立即绑定的符号指针",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "立即绑定"]
        },
        "__got": {
            "purpose": "全局偏移表",
            "content": "全局符号的地址表",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "地址表"]
        },
        "__mod_init_func": {
            "purpose": "模块初始化函数",
            "content": "模块初始化函数指针",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "初始化"]
        },
        "__mod_term_func": {
            "purpose": "模块终止函数",
            "content": "模块终止函数指针",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "终止清理"]
        },
        "__objc_classlist": {
            "purpose": "Objective-C类列表",
            "content": "Objective-C类的指针列表",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "Objective-C", "运行时"]
        },
        "__objc_protolist": {
            "purpose": "Objective-C协议列表",
            "content": "Objective-C协议的指针列表",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "Objective-C", "协议"]
        },
        "__objc_imageinfo": {
            "purpose": "Objective-C镜像信息",
            "content": "Objective-C运行时镜像信息",
            "typical_segment": "__DATA",
            "characteristics": ["可读写", "Objective-C", "元数据"]
        }
    }
    
    # 查找匹配的节用途
    for sec_name, info in section_purposes.items():
        if section_name == sec_name:
            analysis = info.copy()
            analysis["segment_match"] = segment_name == info["typical_segment"]
            return analysis
    
    # 基于节名称模式的分析
    if section_name.startswith("__objc_"):
        return {
            "purpose": "Objective-C运行时数据",
            "content": "Objective-C相关的运行时信息",
            "typical_segment": "__DATA",
            "characteristics": ["Objective-C", "运行时", "元数据"],
            "segment_match": segment_name in ["__DATA", "__DATA_CONST", "__DATA_DIRTY"]
        }
    elif section_name.startswith("__swift"):
        return {
            "purpose": "Swift运行时数据",
            "content": "Swift语言相关的运行时信息",
            "typical_segment": "__TEXT或__DATA",
            "characteristics": ["Swift", "运行时", "元数据"],
            "segment_match": True
        }
    elif "debug" in section_name.lower():
        return {
            "purpose": "调试信息",
            "content": "调试相关的数据和符号",
            "typical_segment": "__DWARF",
            "characteristics": ["调试", "符号信息", "可剥离"],
            "segment_match": True
        }
    
    # 未知节类型
    return {
        "purpose": "自定义或特殊用途节",
        "content": f"节名称: {section_name}",
        "typical_segment": "取决于具体用途",
        "characteristics": ["自定义"],
        "segment_match": True
    }


def _calculate_section_statistics(sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算节统计信息"""
    
    stats = {
        "total_sections": len(sections),
        "total_size": 0,
        "sections_by_segment": {},
        "sections_by_type": {},
        "largest_section": None,
        "smallest_section": None,
        "executable_sections": 0,
        "data_sections": 0,
        "debug_sections": 0
    }
    
    largest_size = 0
    smallest_size = float('inf')
    
    for section in sections:
        if "error" in section:
            continue
        
        # 累计大小
        if "size" in section:
            size = section["size"]["value"]
            stats["total_size"] += size
            
            # 找最大最小节
            if size > largest_size:
                largest_size = size
                stats["largest_section"] = {
                    "name": section["name"],
                    "segment": section["segment_name"],
                    "size": section["size"]
                }
            
            if size < smallest_size and size > 0:
                smallest_size = size
                stats["smallest_section"] = {
                    "name": section["name"],
                    "segment": section["segment_name"],
                    "size": section["size"]
                }
        
        # 按段统计
        segment_name = section.get("segment_name", "unknown")
        stats["sections_by_segment"][segment_name] = stats["sections_by_segment"].get(segment_name, 0) + 1
        
        # 按类型统计
        if "type" in section:
            section_type = section["type"]["value"]
            stats["sections_by_type"][section_type] = stats["sections_by_type"].get(section_type, 0) + 1
        
        # 按用途分类
        if "section_analysis" in section:
            purpose = section["section_analysis"]["purpose"]
            if "代码" in purpose or "指令" in purpose:
                stats["executable_sections"] += 1
            elif "数据" in purpose or "变量" in purpose:
                stats["data_sections"] += 1
            elif "调试" in purpose:
                stats["debug_sections"] += 1
    
    # 格式化总大小
    stats["total_size_formatted"] = _format_size(stats["total_size"])
    
    return stats


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
