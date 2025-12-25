"""
Mach-O 头部信息获取工具

此工具专门用于获取 Mach-O 文件的头部信息，包括文件类型、CPU类型、标志位等关键头部数据。
提供详细的头部结构解析，帮助理解二进制文件的基本属性和特征。
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief

from .common import parse_macho, validate_file_path


def get_macho_header(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )]
) -> Dict[str, Any]:
    """
    获取 Mach-O 文件的头部信息，包括文件类型、CPU类型、标志位等关键头部数据。
    
    该工具解析 Mach-O 文件头部结构，提供：
    - 魔数（Magic Number）信息
    - CPU 类型和子类型详情
    - 文件类型分类
    - 加载命令统计
    - 头部标志位解析
    - 架构特定的头部属性
    
    支持单架构和 Fat Binary 文件的头部信息提取。
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
            "headers": []
        }
        
        # 遍历所有架构的头部信息
        for i, binary in enumerate(fat_binary):
            try:
                header_info = _extract_header_info(binary, i)
                result["headers"].append(header_info)
            except Exception as e:
                result["headers"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 头部时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件头部时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_header_info(binary: lief.MachO.Binary, index: int) -> Dict[str, Any]:
    """提取单个架构的头部详细信息"""
    
    header = binary.header
    
    # 基本头部信息
    header_info = {
        "architecture_index": index,
        "magic": {
            "name": str(header.magic),
            "description": _get_magic_description_by_name(str(header.magic))
        },
        "cpu_type": {
            "name": str(header.cpu_type),
            "description": _get_cpu_type_description(header.cpu_type)
        },
        "cpu_subtype": {
            "name": str(header.cpu_subtype),
            "description": _get_cpu_subtype_description(header.cpu_type, header.cpu_subtype)
        },
        "file_type": {
            "name": str(header.file_type),
            "description": _get_file_type_description(header.file_type)
        },
        "load_commands_count": header.nb_cmds,
        "load_commands_size": header.sizeof_cmds,
        "flags": {
            "value": header.flags,
            "hex": hex(header.flags),
            "parsed_flags": _parse_header_flags(header.flags)
        }
    }
    
    # 添加保留字段（如果存在）
    if hasattr(header, 'reserved'):
        header_info["reserved"] = header.reserved
    
    # 计算头部大小
    header_info["header_size"] = _calculate_header_size(header)
    
    # 添加架构特定信息
    try:
        header_info["architecture_info"] = {
            "is_64bit": _is_64bit_architecture(header.cpu_type),
            "endianness": _get_endianness(header.magic),
            "platform": _get_platform_info(header.cpu_type)
        }
    except Exception as e:
        header_info["architecture_info"] = {
            "error": f"获取架构信息时发生错误: {str(e)}",
            "is_64bit": None,
            "endianness": _get_endianness(header.magic),
            "platform": "未知平台"
        }
    
    return header_info


def _get_magic_description_by_name(magic_name: str) -> str:
    """根据魔数名称获取描述"""
    magic_descriptions = {
        "MH_MAGIC": "32-bit Mach-O binary",
        "MH_MAGIC_64": "64-bit Mach-O binary", 
        "MH_CIGAM": "32-bit Mach-O binary, reverse byte order",
        "MH_CIGAM_64": "64-bit Mach-O binary, reverse byte order",
        "FAT_MAGIC": "Fat binary",
        "FAT_CIGAM": "Fat binary, reverse byte order"
    }
    return magic_descriptions.get(magic_name, f"魔数类型: {magic_name}")


def _get_cpu_type_description(cpu_type) -> str:
    """获取CPU类型的描述"""
    try:
        cpu_name = str(cpu_type)
        descriptions = {
            "X86": "Intel x86 架构",
            "X86_64": "Intel x86-64 架构",
            "ARM": "ARM 架构",
            "ARM64": "ARM64 架构",
            "PPC": "PowerPC 架构",
            "PPC64": "PowerPC 64位架构"
        }
        
        for key, desc in descriptions.items():
            if key in cpu_name:
                return desc
        
        return f"CPU架构: {cpu_name}"
    except:
        return "未知CPU架构"


def _get_cpu_subtype_description(cpu_type, cpu_subtype) -> str:
    """获取CPU子类型的描述"""
    try:
        subtype_name = str(cpu_subtype)
        
        # 根据CPU类型提供更详细的子类型描述
        if "ARM64" in str(cpu_type):
            if "ALL" in subtype_name:
                return "ARM64 通用子类型"
            elif "V8" in subtype_name:
                return "ARM64 v8 架构"
        elif "X86_64" in str(cpu_type):
            if "ALL" in subtype_name:
                return "x86-64 通用子类型"
        
        return f"子类型: {subtype_name}"
    except:
        return "未知子类型"


def _get_file_type_description(file_type) -> str:
    """获取文件类型的描述"""
    try:
        type_name = str(file_type)
        descriptions = {
            "OBJECT": "目标文件 (.o)",
            "EXECUTE": "可执行文件",
            "DYLIB": "动态库 (.dylib)",
            "DYLINKER": "动态链接器",
            "BUNDLE": "Bundle 文件",
            "PRELOAD": "预加载可执行文件",
            "CORE": "核心转储文件",
            "DYLIB_STUB": "动态库存根",
            "DSYM": "调试符号文件"
        }
        
        for key, desc in descriptions.items():
            if key in type_name:
                return desc
        
        return f"文件类型: {type_name}"
    except:
        return "未知文件类型"


def _parse_header_flags(flags: int) -> List[Dict[str, Any]]:
    """解析头部标志位"""
    flag_definitions = [
        (0x1, "MH_NOUNDEFS", "文件中没有未定义的符号"),
        (0x2, "MH_INCRLINK", "文件是增量链接的输出"),
        (0x4, "MH_DYLDLINK", "文件被动态链接器链接"),
        (0x8, "MH_BINDATLOAD", "文件在加载时绑定未定义的引用"),
        (0x10, "MH_PREBOUND", "文件已预绑定"),
        (0x20, "MH_SPLIT_SEGS", "文件的只读和读写段分离"),
        (0x40, "MH_LAZY_INIT", "共享库的初始化例程在第一次使用时调用"),
        (0x80, "MH_TWOLEVEL", "文件使用两级名称空间绑定"),
        (0x100, "MH_FORCE_FLAT", "可执行文件强制使用平面名称空间绑定"),
        (0x200, "MH_NOMULTIDEFS", "文件中没有多重定义的符号"),
        (0x400, "MH_NOFIXPREBINDING", "不要通知预绑定代理"),
        (0x800, "MH_PREBINDABLE", "二进制文件不可预绑定"),
        (0x1000, "MH_ALLMODSBOUND", "指示动态链接器所有模块都已绑定"),
        (0x2000, "MH_SUBSECTIONS_VIA_SYMBOLS", "安全地将文件分成子段"),
        (0x4000, "MH_CANONICAL", "二进制文件已规范化"),
        (0x8000, "MH_WEAK_DEFINES", "最终链接的镜像包含外部弱符号"),
        (0x10000, "MH_BINDS_TO_WEAK", "最终链接的镜像使用弱符号"),
        (0x20000, "MH_ALLOW_STACK_EXECUTION", "当此位设置时，所有栈都是可执行的"),
        (0x40000, "MH_ROOT_SAFE", "二进制文件对于使用setuid的程序是安全的"),
        (0x80000, "MH_SETUID_SAFE", "二进制文件对于使用setuid的程序是安全的"),
        (0x100000, "MH_NO_REEXPORTED_DYLIBS", "此可执行文件不重新导出任何动态库"),
        (0x200000, "MH_PIE", "加载时随机化虚拟内存地址"),
        (0x400000, "MH_DEAD_STRIPPABLE_DYLIB", "包含可以安全删除的死代码"),
        (0x800000, "MH_HAS_TLV_DESCRIPTORS", "包含线程局部变量描述符段"),
        (0x1000000, "MH_NO_HEAP_EXECUTION", "没有堆执行")
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


def _calculate_header_size(header) -> int:
    """计算头部大小"""
    try:
        # 根据魔数确定头部大小
        if hasattr(header, 'magic'):
            magic_name = str(header.magic)
            if "64" in magic_name:  # 64位
                return 32  # mach_header_64 大小
            else:  # 32位
                return 28  # mach_header 大小
        return 28  # 默认32位头部大小
    except:
        return 0


def _is_64bit_architecture(cpu_type) -> bool:
    """判断是否为64位架构"""
    try:
        cpu_name = str(cpu_type)
        return "64" in cpu_name or "ARM64" in cpu_name
    except:
        return False


def _get_endianness(magic) -> str:
    """获取字节序信息"""
    try:
        magic_name = str(magic)
        if "CIGAM" in magic_name:
            return "big_endian"
        else:
            return "little_endian"
    except:
        return "unknown_endian"


def _get_platform_info(cpu_type) -> str:
    """获取平台信息"""
    try:
        cpu_name = str(cpu_type)
        if "ARM" in cpu_name:
            return "iOS/macOS (Apple Silicon)"
        elif "X86" in cpu_name:
            return "macOS (Intel)"
        elif "PPC" in cpu_name:
            return "macOS (PowerPC)"
        else:
            return "未知平台"
    except:
        return "未知平台"
