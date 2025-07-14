"""
Mach-O 文件信息解析工具

此工具用于解析 Mach-O 文件的基本信息，包括架构、文件类型、入口点等核心属性。
支持 Fat Binary 和单架构文件，提供详细的结构化信息输出。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os


def parse_macho_info(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )]
) -> Dict[str, Any]:
    """
    解析 Mach-O 文件的基本信息，包括架构、文件类型、入口点等核心属性。
    
    支持解析：
    - 单架构 Mach-O 文件
    - Fat Binary（多架构）文件
    - .app 包内的可执行文件
    - 系统二进制文件和动态库
    
    返回包含文件基本信息、架构详情、段节统计等结构化数据。
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
        
        # 获取文件基本信息
        file_stat = os.stat(file_path)
        file_size = file_stat.st_size
        
        # 解析 Mach-O 文件
        fat_binary = lief.MachO.parse(file_path)
        
        if fat_binary is None:
            return {
                "error": "无法解析文件，可能不是有效的 Mach-O 文件",
                "file_path": file_path,
                "file_size": file_size,
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        # 构建基本结果信息
        result = {
            "file_path": file_path,
            "file_size": file_size,
            "file_size_human": _format_file_size(file_size),
            "is_fat_binary": len(fat_binary) > 1,
            "architecture_count": len(fat_binary),
            "architectures": []
        }
        
        # 遍历所有架构
        for i, binary in enumerate(fat_binary):
            try:
                arch_info = _extract_architecture_info(binary, i)
                result["architectures"].append(arch_info)
            except Exception as e:
                result["architectures"].append({
                    "index": i,
                    "error": f"解析架构 {i} 时发生错误: {str(e)}"
                })
        
        # 添加汇总信息
        if result["architectures"]:
            result["summary"] = _generate_summary(result["architectures"])
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_architecture_info(binary: lief.MachO.Binary, index: int) -> Dict[str, Any]:
    """提取单个架构的详细信息"""
    
    # 基本架构信息
    arch_info = {
        "index": index,
        "cpu_type": str(binary.header.cpu_type),
        "cpu_subtype": str(binary.header.cpu_subtype),
        "file_type": str(binary.header.file_type),
        "entrypoint": hex(binary.entrypoint),
        "entrypoint_decimal": binary.entrypoint,
    }
    
    # 统计信息
    arch_info["statistics"] = {
        "load_commands_count": len(binary.commands),
        "segments_count": len(binary.segments),
        "sections_count": len(binary.sections),
        "symbols_count": len(binary.symbols),
        "imported_symbols_count": len(binary.imported_symbols),
        "exported_functions_count": len(binary.exported_functions)
    }
    
    # 段信息概览
    segments_info = []
    for segment in binary.segments:
        seg_info = {
            "name": segment.name,
            "virtual_address": hex(segment.virtual_address),
            "virtual_size": segment.virtual_size,
            "file_offset": segment.file_offset,
            "file_size": segment.file_size,
            "sections_count": len(segment.sections)
        }
        segments_info.append(seg_info)
    
    arch_info["segments"] = segments_info
    
    # 依赖库信息
    libraries = []
    for lib in binary.libraries:
        libraries.append({
            "name": lib.name,
            "timestamp": lib.timestamp,
            "current_version": f"{lib.current_version[0]}.{lib.current_version[1]}.{lib.current_version[2]}",
            "compatibility_version": f"{lib.compatibility_version[0]}.{lib.compatibility_version[1]}.{lib.compatibility_version[2]}"
        })
    
    arch_info["libraries"] = libraries
    
    # 特殊属性检查
    arch_info["properties"] = {
        "has_entrypoint": binary.has_entrypoint,
        "has_uuid": binary.has_uuid,
        "has_main_command": binary.has_main_command,
        "has_dylinker": binary.has_dylinker,
        "has_dyld_info": binary.has_dyld_info,
        "is_pie": binary.is_pie if hasattr(binary, 'is_pie') else None
    }
    
    # UUID 信息（如果存在）
    if binary.has_uuid:
        try:
            uuid_cmd = binary.uuid
            arch_info["uuid"] = list(uuid_cmd.uuid)
        except:
            arch_info["uuid"] = "无法获取 UUID"
    
    return arch_info


def _generate_summary(architectures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成架构汇总信息"""
    
    cpu_types = set()
    file_types = set()
    total_segments = 0
    total_sections = 0
    total_symbols = 0
    
    for arch in architectures:
        if "error" not in arch:
            cpu_types.add(arch["cpu_type"])
            file_types.add(arch["file_type"])
            stats = arch.get("statistics", {})
            total_segments += stats.get("segments_count", 0)
            total_sections += stats.get("sections_count", 0)
            total_symbols += stats.get("symbols_count", 0)
    
    return {
        "unique_cpu_types": list(cpu_types),
        "unique_file_types": list(file_types),
        "total_segments": total_segments,
        "total_sections": total_sections,
        "total_symbols": total_symbols
    }


def _format_file_size(size_bytes: int) -> str:
    """格式化文件大小为人类可读格式"""
    
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
