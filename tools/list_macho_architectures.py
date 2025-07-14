"""
Mach-O Fat Binary 架构列表工具

此工具专门用于列出 Fat Binary 中的所有架构信息，提供简洁的架构概览。
适用于快速查看多架构二进制文件的架构组成，无需获取详细的文件信息。
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief
import os


def list_macho_architectures(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )]
) -> Dict[str, Any]:
    """
    列出 Fat Binary 中的所有架构信息。
    
    专门用于快速查看多架构二进制文件的架构组成，提供：
    - 架构类型和子类型
    - 文件类型信息
    - 架构索引和基本属性
    - 简洁的架构汇总
    
    对于单架构文件也会正常显示其架构信息。
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
        
        # 构建结果信息
        result = {
            "file_path": file_path,
            "is_fat_binary": len(fat_binary) > 1,
            "architecture_count": len(fat_binary),
            "architectures": []
        }
        
        # 遍历所有架构
        for i, binary in enumerate(fat_binary):
            try:
                arch_info = _extract_architecture_summary(binary, i)
                result["architectures"].append(arch_info)
            except Exception as e:
                result["architectures"].append({
                    "index": i,
                    "error": f"解析架构 {i} 时发生错误: {str(e)}"
                })
        
        # 添加架构汇总
        if result["architectures"]:
            result["summary"] = _generate_architecture_summary(result["architectures"])
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_architecture_summary(binary: lief.MachO.Binary, index: int) -> Dict[str, Any]:
    """提取单个架构的简要信息"""
    
    # 获取 CPU 类型的友好名称
    cpu_type_name = _get_cpu_type_name(binary.header.cpu_type)
    cpu_subtype_name = _get_cpu_subtype_name(binary.header.cpu_type, binary.header.cpu_subtype)
    file_type_name = _get_file_type_name(binary.header.file_type)
    
    arch_info = {
        "index": index,
        "cpu_type": str(binary.header.cpu_type),
        "cpu_type_name": cpu_type_name,
        "cpu_subtype": str(binary.header.cpu_subtype),
        "cpu_subtype_name": cpu_subtype_name,
        "file_type": str(binary.header.file_type),
        "file_type_name": file_type_name,
        "architecture_string": f"{cpu_type_name}_{cpu_subtype_name}",
        "has_entrypoint": binary.has_entrypoint,
        "entrypoint": hex(binary.entrypoint) if binary.has_entrypoint else None
    }
    
    return arch_info


def _generate_architecture_summary(architectures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成架构汇总信息"""
    
    cpu_types = set()
    cpu_type_names = set()
    file_types = set()
    architecture_strings = []
    
    for arch in architectures:
        if "error" not in arch:
            cpu_types.add(arch["cpu_type"])
            cpu_type_names.add(arch["cpu_type_name"])
            file_types.add(arch["file_type_name"])
            architecture_strings.append(arch["architecture_string"])
    
    return {
        "unique_cpu_types": list(cpu_types),
        "unique_cpu_type_names": list(cpu_type_names),
        "unique_file_types": list(file_types),
        "architecture_strings": architecture_strings,
        "architecture_list": ", ".join(architecture_strings)
    }


def _get_cpu_type_name(cpu_type) -> str:
    """获取 CPU 类型的友好名称"""
    
    cpu_type_map = {
        "CPU_TYPE_X86": "x86",
        "CPU_TYPE_X86_64": "x86_64",
        "CPU_TYPE_ARM": "arm",
        "CPU_TYPE_ARM64": "arm64",
        "CPU_TYPE_POWERPC": "ppc",
        "CPU_TYPE_POWERPC64": "ppc64",
        "CPU_TYPE_I386": "i386",
        "CPU_TYPE_SPARC": "sparc",
        "CPU_TYPE_MC680x0": "m68k",
        "CPU_TYPE_HPPA": "hppa",
        "CPU_TYPE_MC88000": "m88k"
    }
    
    cpu_type_str = str(cpu_type)
    return cpu_type_map.get(cpu_type_str, cpu_type_str)


def _get_cpu_subtype_name(cpu_type, cpu_subtype) -> str:
    """获取 CPU 子类型的友好名称"""
    
    cpu_type_str = str(cpu_type)
    cpu_subtype_str = str(cpu_subtype)
    
    # x86_64 子类型
    if cpu_type_str == "CPU_TYPE_X86_64":
        x86_64_subtypes = {
            "CPU_SUBTYPE_X86_64_ALL": "all",
            "CPU_SUBTYPE_X86_64_H": "haswell"
        }
        return x86_64_subtypes.get(cpu_subtype_str, cpu_subtype_str)
    
    # ARM64 子类型
    elif cpu_type_str == "CPU_TYPE_ARM64":
        arm64_subtypes = {
            "CPU_SUBTYPE_ARM64_ALL": "all",
            "CPU_SUBTYPE_ARM64_V8": "v8",
            "CPU_SUBTYPE_ARM64E": "e"
        }
        return arm64_subtypes.get(cpu_subtype_str, cpu_subtype_str)
    
    # ARM 子类型
    elif cpu_type_str == "CPU_TYPE_ARM":
        arm_subtypes = {
            "CPU_SUBTYPE_ARM_ALL": "all",
            "CPU_SUBTYPE_ARM_V4T": "v4t",
            "CPU_SUBTYPE_ARM_V5TEJ": "v5tej",
            "CPU_SUBTYPE_ARM_V6": "v6",
            "CPU_SUBTYPE_ARM_V6M": "v6m",
            "CPU_SUBTYPE_ARM_V7": "v7",
            "CPU_SUBTYPE_ARM_V7F": "v7f",
            "CPU_SUBTYPE_ARM_V7S": "v7s",
            "CPU_SUBTYPE_ARM_V7K": "v7k",
            "CPU_SUBTYPE_ARM_V7M": "v7m",
            "CPU_SUBTYPE_ARM_V7EM": "v7em"
        }
        return arm_subtypes.get(cpu_subtype_str, cpu_subtype_str)
    
    # x86 子类型
    elif cpu_type_str == "CPU_TYPE_X86" or cpu_type_str == "CPU_TYPE_I386":
        x86_subtypes = {
            "CPU_SUBTYPE_I386_ALL": "all",
            "CPU_SUBTYPE_386": "386",
            "CPU_SUBTYPE_486": "486",
            "CPU_SUBTYPE_486SX": "486sx",
            "CPU_SUBTYPE_586": "586",
            "CPU_SUBTYPE_PENT": "pentium",
            "CPU_SUBTYPE_PENTPRO": "pentium_pro",
            "CPU_SUBTYPE_PENTII_M3": "pentium_ii_m3",
            "CPU_SUBTYPE_PENTII_M5": "pentium_ii_m5",
            "CPU_SUBTYPE_CELERON": "celeron",
            "CPU_SUBTYPE_CELERON_MOBILE": "celeron_mobile",
            "CPU_SUBTYPE_PENTIUM_3": "pentium_3",
            "CPU_SUBTYPE_PENTIUM_3_M": "pentium_3_m",
            "CPU_SUBTYPE_PENTIUM_3_XEON": "pentium_3_xeon",
            "CPU_SUBTYPE_PENTIUM_M": "pentium_m",
            "CPU_SUBTYPE_PENTIUM_4": "pentium_4",
            "CPU_SUBTYPE_PENTIUM_4_M": "pentium_4_m",
            "CPU_SUBTYPE_ITANIUM": "itanium",
            "CPU_SUBTYPE_ITANIUM_2": "itanium_2",
            "CPU_SUBTYPE_XEON": "xeon",
            "CPU_SUBTYPE_XEON_MP": "xeon_mp"
        }
        return x86_subtypes.get(cpu_subtype_str, cpu_subtype_str)
    
    # 默认返回原始字符串
    return cpu_subtype_str


def _get_file_type_name(file_type) -> str:
    """获取文件类型的友好名称"""
    
    file_type_map = {
        "MH_OBJECT": "object",
        "MH_EXECUTE": "executable",
        "MH_FVMLIB": "fvmlib",
        "MH_CORE": "core",
        "MH_PRELOAD": "preload",
        "MH_DYLIB": "dylib",
        "MH_DYLINKER": "dylinker",
        "MH_BUNDLE": "bundle",
        "MH_DYLIB_STUB": "dylib_stub",
        "MH_DSYM": "dsym",
        "MH_KEXT_BUNDLE": "kext_bundle"
    }
    
    file_type_str = str(file_type)
    return file_type_map.get(file_type_str, file_type_str)
