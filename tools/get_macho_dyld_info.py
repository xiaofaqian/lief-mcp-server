"""
Mach-O Dyld 信息获取工具

此工具专门用于获取 Mach-O 文件中的 dyld 信息，包括绑定信息、重定位信息、导出信息、重基址信息等详细数据。
提供完整的 dyld 信息解析，帮助理解二进制文件的动态链接器配置和运行时行为。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os


def get_macho_dyld_info(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    include_bindings: Annotated[bool, Field(
        description="是否包含绑定信息（binding info）"
    )] = True,
    include_rebases: Annotated[bool, Field(
        description="是否包含重基址信息（rebase info）"
    )] = True,
    include_exports: Annotated[bool, Field(
        description="是否包含导出信息（export info）"
    )] = True,
    include_opcodes: Annotated[bool, Field(
        description="是否包含字节码操作码的伪代码显示"
    )] = False,
    include_relocations: Annotated[bool, Field(
        description="是否包含重定位信息（relocations）"
    )] = True
) -> Dict[str, Any]:
    """
    获取 Mach-O 文件中的 dyld 信息，包括绑定、重定位、导出、重基址等详细数据。
    
    该工具解析 Mach-O 文件的 dyld 信息结构，提供：
    - 绑定信息（符号绑定、延迟绑定、弱绑定）
    - 重基址信息（地址重定位）
    - 导出信息（导出符号和导出 trie）
    - 重定位信息（解释后的重定位对象）
    - 字节码操作码的伪代码显示
    - dyld 信息统计和分析
    
    支持单架构和 Fat Binary 文件的 dyld 信息提取。
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
        
        # 遍历所有架构的 dyld 信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_dyld_info = _extract_dyld_info(
                    binary, i, include_bindings, include_rebases, 
                    include_exports, include_opcodes, include_relocations
                )
                result["architectures"].append(arch_dyld_info)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} dyld 信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件 dyld 信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_dyld_info(
    binary: lief.MachO.Binary, 
    index: int,
    include_bindings: bool = True,
    include_rebases: bool = True,
    include_exports: bool = True,
    include_opcodes: bool = False,
    include_relocations: bool = True
) -> Dict[str, Any]:
    """提取单个架构的 dyld 详细信息"""
    
    header = binary.header
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "has_dyld_info": hasattr(binary, 'dyld_info') and binary.dyld_info is not None
    }
    
    # 如果没有 dyld_info，返回基本信息
    if not arch_info["has_dyld_info"]:
        arch_info["warning"] = "此架构没有 dyld 信息"
        return arch_info
    
    dyld_info = binary.dyld_info
    
    # 添加 dyld_info 基本信息
    arch_info["dyld_info_basic"] = _extract_dyld_info_basic(dyld_info)
    
    # 添加绑定信息
    if include_bindings:
        try:
            arch_info["bindings"] = _extract_bindings_info(binary)
        except Exception as e:
            arch_info["bindings_error"] = f"解析绑定信息时发生错误: {str(e)}"
    
    # 添加重基址信息
    if include_rebases:
        try:
            arch_info["rebases"] = _extract_rebases_info(binary)
        except Exception as e:
            arch_info["rebases_error"] = f"解析重基址信息时发生错误: {str(e)}"
    
    # 添加导出信息
    if include_exports:
        try:
            arch_info["exports"] = _extract_exports_info(binary)
        except Exception as e:
            arch_info["exports_error"] = f"解析导出信息时发生错误: {str(e)}"
    
    # 添加重定位信息
    if include_relocations:
        try:
            arch_info["relocations"] = _extract_relocations_info(binary)
        except Exception as e:
            arch_info["relocations_error"] = f"解析重定位信息时发生错误: {str(e)}"
    
    # 添加字节码操作码信息
    if include_opcodes:
        try:
            arch_info["opcodes"] = _extract_opcodes_info(dyld_info)
        except Exception as e:
            arch_info["opcodes_error"] = f"解析操作码信息时发生错误: {str(e)}"
    
    # 添加统计信息
    arch_info["dyld_statistics"] = _calculate_dyld_statistics(arch_info)
    
    return arch_info


def _extract_dyld_info_basic(dyld_info) -> Dict[str, Any]:
    """提取 dyld_info 的基本信息"""
    
    basic_info = {}
    
    # 基本属性
    try:
        if hasattr(dyld_info, 'rebase_opcodes') and dyld_info.rebase_opcodes:
            basic_info["rebase_opcodes_size"] = len(dyld_info.rebase_opcodes)
        else:
            basic_info["rebase_opcodes_size"] = 0
    except Exception:
        basic_info["rebase_opcodes_size"] = "无法获取"
    
    try:
        if hasattr(dyld_info, 'bind_opcodes') and dyld_info.bind_opcodes:
            basic_info["bind_opcodes_size"] = len(dyld_info.bind_opcodes)
        else:
            basic_info["bind_opcodes_size"] = 0
    except Exception:
        basic_info["bind_opcodes_size"] = "无法获取"
    
    try:
        if hasattr(dyld_info, 'weak_bind_opcodes') and dyld_info.weak_bind_opcodes:
            basic_info["weak_bind_opcodes_size"] = len(dyld_info.weak_bind_opcodes)
        else:
            basic_info["weak_bind_opcodes_size"] = 0
    except Exception:
        basic_info["weak_bind_opcodes_size"] = "无法获取"
    
    try:
        if hasattr(dyld_info, 'lazy_bind_opcodes') and dyld_info.lazy_bind_opcodes:
            basic_info["lazy_bind_opcodes_size"] = len(dyld_info.lazy_bind_opcodes)
        else:
            basic_info["lazy_bind_opcodes_size"] = 0
    except Exception:
        basic_info["lazy_bind_opcodes_size"] = "无法获取"
    
    try:
        if hasattr(dyld_info, 'export_trie') and dyld_info.export_trie:
            basic_info["export_trie_size"] = len(dyld_info.export_trie)
        else:
            basic_info["export_trie_size"] = 0
    except Exception:
        basic_info["export_trie_size"] = "无法获取"
    
    return basic_info


def _extract_bindings_info(binary: lief.MachO.Binary) -> Dict[str, Any]:
    """提取绑定信息"""
    
    bindings_info = {
        "total_bindings": 0,
        "binding_types": {},
        "binding_classes": {},
        "bindings": []
    }
    
    for binding in binary.bindings:
        bindings_info["total_bindings"] += 1
        
        try:
            binding_data = {
                "address": binding.address,
                "addend": binding.addend,
                "library_ordinal": binding.library_ordinal,
                "weak_import": binding.weak_import
            }
            
            # 添加符号信息
            if binding.has_symbol:
                symbol = binding.symbol
                binding_data["symbol"] = {
                    "name": symbol.name,
                    "demangled_name": getattr(symbol, 'demangled_name', symbol.name),
                    "type": str(symbol.type),
                    "category": str(symbol.category)
                }
            
            # 添加库信息
            if binding.has_library:
                library = binding.library
                binding_data["library"] = {
                    "name": library.name,
                    "current_version": library.current_version,
                    "compatibility_version": library.compatibility_version
                }
            
            # 添加段信息
            if binding.has_segment:
                segment = binding.segment
                binding_data["segment"] = {
                    "name": segment.name,
                    "virtual_address": segment.virtual_address,
                    "file_offset": segment.file_offset
                }
            
            # 分析绑定类型和类别
            if hasattr(binding, 'binding_class'):
                binding_class = str(binding.binding_class)
                binding_data["binding_class"] = {
                    "value": binding_class,
                    "description": _get_binding_class_description(binding_class)
                }
                bindings_info["binding_classes"][binding_class] = bindings_info["binding_classes"].get(binding_class, 0) + 1
            
            if hasattr(binding, 'binding_type'):
                binding_type = str(binding.binding_type)
                binding_data["binding_type"] = {
                    "value": binding_type,
                    "description": _get_binding_type_description(binding_type)
                }
                bindings_info["binding_types"][binding_type] = bindings_info["binding_types"].get(binding_type, 0) + 1
            
            bindings_info["bindings"].append(binding_data)
            
        except Exception as e:
            bindings_info["bindings"].append({
                "error": f"解析绑定项时发生错误: {str(e)}"
            })
    
    return bindings_info


def _extract_rebases_info(binary: lief.MachO.Binary) -> Dict[str, Any]:
    """提取重基址信息"""
    
    rebases_info = {
        "total_rebases": 0,
        "rebase_types": {},
        "rebases": []
    }
    
    # 检查是否有重基址信息
    if not hasattr(binary, 'relocations'):
        rebases_info["warning"] = "此二进制文件没有重基址信息"
        return rebases_info
    
    # 从重定位信息中提取重基址相关信息
    for relocation in binary.relocations:
        try:
            # 检查是否是重基址类型的重定位
            reloc_str = str(relocation)
            if "DYLDINFO" in reloc_str or "REBASE" in reloc_str:
                rebases_info["total_rebases"] += 1
                
                rebase_data = {
                    "address": getattr(relocation, 'address', 0),
                    "size": getattr(relocation, 'size', 0),
                    "type": str(getattr(relocation, 'type', 'UNKNOWN')),
                    "pc_relative": getattr(relocation, 'pc_relative', False),
                    "is_scattered": getattr(relocation, 'is_scattered', False)
                }
                
                # 添加符号信息（如果有）
                if hasattr(relocation, 'has_symbol') and relocation.has_symbol:
                    symbol = relocation.symbol
                    rebase_data["symbol"] = {
                        "name": symbol.name,
                        "value": symbol.value
                    }
                
                # 添加段信息（如果有）
                if hasattr(relocation, 'has_segment') and relocation.has_segment:
                    segment = relocation.segment
                    rebase_data["segment"] = {
                        "name": segment.name,
                        "virtual_address": segment.virtual_address
                    }
                
                # 统计重基址类型
                rebase_type = str(getattr(relocation, 'type', 'UNKNOWN'))
                rebases_info["rebase_types"][rebase_type] = rebases_info["rebase_types"].get(rebase_type, 0) + 1
                
                rebases_info["rebases"].append(rebase_data)
                
        except Exception as e:
            rebases_info["rebases"].append({
                "error": f"解析重基址项时发生错误: {str(e)}"
            })
    
    return rebases_info


def _extract_exports_info(binary: lief.MachO.Binary) -> Dict[str, Any]:
    """提取导出信息"""
    
    exports_info = {
        "total_exports": 0,
        "export_kinds": {},
        "exports": []
    }
    
    for export_symbol in binary.exported_symbols:
        exports_info["total_exports"] += 1
        
        try:
            export_data = {
                "name": export_symbol.name,
                "demangled_name": getattr(export_symbol, 'demangled_name', export_symbol.name),
                "value": getattr(export_symbol, 'value', 0)
            }
            
            # 添加导出信息详情
            if hasattr(export_symbol, 'has_export_info') and export_symbol.has_export_info:
                exp_info = export_symbol.export_info
                export_data["export_info"] = {
                    "address": exp_info.address,
                    "flags": exp_info.flags,
                    "kind": {
                        "value": str(exp_info.kind),
                        "description": _get_export_kind_description(str(exp_info.kind))
                    },
                    "node_offset": exp_info.node_offset
                }
                
                # 统计导出类型
                export_kind = str(exp_info.kind)
                exports_info["export_kinds"][export_kind] = exports_info["export_kinds"].get(export_kind, 0) + 1
            
            exports_info["exports"].append(export_data)
            
        except Exception as e:
            exports_info["exports"].append({
                "name": getattr(export_symbol, 'name', 'unknown'),
                "error": f"解析导出项时发生错误: {str(e)}"
            })
    
    return exports_info


def _extract_relocations_info(binary: lief.MachO.Binary) -> Dict[str, Any]:
    """提取重定位信息"""
    
    relocations_info = {
        "total_relocations": 0,
        "relocation_types": {},
        "relocations": []
    }
    
    for relocation in binary.relocations:
        relocations_info["total_relocations"] += 1
        
        try:
            reloc_data = {
                "address": getattr(relocation, 'address', 0),
                "size": getattr(relocation, 'size', 0),
                "pc_relative": getattr(relocation, 'pc_relative', False),
                "is_scattered": getattr(relocation, 'is_scattered', False)
            }
            
            # 添加重定位类型
            try:
                reloc_type = str(relocation.type)
                reloc_data["type"] = {
                    "value": reloc_type,
                    "description": _get_relocation_type_description(reloc_type)
                }
                relocations_info["relocation_types"][reloc_type] = relocations_info["relocation_types"].get(reloc_type, 0) + 1
            except Exception:
                reloc_data["type"] = {"value": "UNKNOWN", "description": "无法获取重定位类型"}
            
            # 添加符号信息
            if hasattr(relocation, 'has_symbol') and relocation.has_symbol:
                symbol = relocation.symbol
                reloc_data["symbol"] = {
                    "name": symbol.name,
                    "value": symbol.value,
                    "type": str(symbol.type)
                }
            
            # 添加段信息
            if hasattr(relocation, 'has_segment') and relocation.has_segment:
                segment = relocation.segment
                reloc_data["segment"] = {
                    "name": segment.name,
                    "virtual_address": segment.virtual_address
                }
            
            # 添加节信息
            if hasattr(relocation, 'has_section') and relocation.has_section:
                section = relocation.section
                reloc_data["section"] = {
                    "name": section.name,
                    "virtual_address": section.virtual_address
                }
            
            relocations_info["relocations"].append(reloc_data)
            
        except Exception as e:
            relocations_info["relocations"].append({
                "error": f"解析重定位项时发生错误: {str(e)}"
            })
    
    return relocations_info


def _extract_opcodes_info(dyld_info) -> Dict[str, Any]:
    """提取字节码操作码信息"""
    
    opcodes_info = {}
    
    # 重基址操作码
    try:
        if hasattr(dyld_info, 'show_rebases_opcodes'):
            opcodes_info["rebase_opcodes"] = str(dyld_info.show_rebases_opcodes)
        else:
            opcodes_info["rebase_opcodes"] = "不可用"
    except Exception as e:
        opcodes_info["rebase_opcodes"] = f"获取重基址操作码时发生错误: {str(e)}"
    
    # 绑定操作码
    try:
        if hasattr(dyld_info, 'show_bind_opcodes'):
            opcodes_info["bind_opcodes"] = str(dyld_info.show_bind_opcodes)
        else:
            opcodes_info["bind_opcodes"] = "不可用"
    except Exception as e:
        opcodes_info["bind_opcodes"] = f"获取绑定操作码时发生错误: {str(e)}"
    
    # 导出 trie
    try:
        if hasattr(dyld_info, 'show_export_trie'):
            opcodes_info["export_trie"] = str(dyld_info.show_export_trie)
        else:
            opcodes_info["export_trie"] = "不可用"
    except Exception as e:
        opcodes_info["export_trie"] = f"获取导出 trie 时发生错误: {str(e)}"
    
    return opcodes_info


def _get_binding_class_description(binding_class: str) -> str:
    """获取绑定类别的描述"""
    
    class_descriptions = {
        "WEAK": "弱绑定，允许符号不存在",
        "LAZY": "延迟绑定，首次使用时才解析",
        "STANDARD": "标准绑定，加载时立即解析",
        "THREADED": "线程化绑定，用于优化性能"
    }
    
    return class_descriptions.get(binding_class, f"未知绑定类别: {binding_class}")


def _get_binding_type_description(binding_type: str) -> str:
    """获取绑定类型的描述"""
    
    type_descriptions = {
        "POINTER": "指针绑定，最常见的绑定类型",
        "TEXT_ABSOLUTE32": "32位绝对文本绑定",
        "TEXT_PCREL32": "32位相对文本绑定"
    }
    
    return type_descriptions.get(binding_type, f"未知绑定类型: {binding_type}")


def _get_export_kind_description(kind: str) -> str:
    """获取导出类型的描述"""
    
    kind_descriptions = {
        "REGULAR": "常规导出符号",
        "THREAD_LOCAL": "线程本地存储符号",
        "ABSOLUTE": "绝对地址符号"
    }
    
    return kind_descriptions.get(kind, f"未知导出类型: {kind}")


def _get_relocation_type_description(reloc_type: str) -> str:
    """获取重定位类型的描述"""
    
    type_descriptions = {
        "VANILLA": "标准重定位",
        "PAIR": "配对重定位",
        "SECTDIFF": "节差异重定位",
        "LOCAL_SECTDIFF": "本地节差异重定位",
        "PB_LA_PTR": "预绑定延迟指针重定位",
        "GENERIC_RELOC_VANILLA": "通用标准重定位",
        "GENERIC_RELOC_PAIR": "通用配对重定位",
        "GENERIC_RELOC_SECTDIFF": "通用节差异重定位",
        "GENERIC_RELOC_PB_LA_PTR": "通用预绑定延迟指针重定位",
        "GENERIC_RELOC_LOCAL_SECTDIFF": "通用本地节差异重定位",
        "GENERIC_RELOC_TLV": "通用线程本地变量重定位"
    }
    
    return type_descriptions.get(reloc_type, f"未知重定位类型: {reloc_type}")


def _calculate_dyld_statistics(arch_info: Dict[str, Any]) -> Dict[str, Any]:
    """计算 dyld 统计信息"""
    
    stats = {
        "has_dyld_info": arch_info.get("has_dyld_info", False),
        "total_bindings": 0,
        "total_rebases": 0,
        "total_exports": 0,
        "total_relocations": 0,
        "binding_classes_count": 0,
        "binding_types_count": 0,
        "export_kinds_count": 0,
        "relocation_types_count": 0,
        "weak_imports": 0,
        "lazy_bindings": 0,
        "opcodes_available": {}
    }
    
    # 绑定统计
    if "bindings" in arch_info and not isinstance(arch_info["bindings"], str):
        bindings = arch_info["bindings"]
        stats["total_bindings"] = bindings.get("total_bindings", 0)
        stats["binding_classes_count"] = len(bindings.get("binding_classes", {}))
        stats["binding_types_count"] = len(bindings.get("binding_types", {}))
        
        # 统计弱导入和延迟绑定
        for binding in bindings.get("bindings", []):
            if binding.get("weak_import", False):
                stats["weak_imports"] += 1
            if binding.get("binding_class", {}).get("value") == "LAZY":
                stats["lazy_bindings"] += 1
    
    # 重基址统计
    if "rebases" in arch_info and not isinstance(arch_info["rebases"], str):
        rebases = arch_info["rebases"]
        stats["total_rebases"] = rebases.get("total_rebases", 0)
    
    # 导出统计
    if "exports" in arch_info and not isinstance(arch_info["exports"], str):
        exports = arch_info["exports"]
        stats["total_exports"] = exports.get("total_exports", 0)
        stats["export_kinds_count"] = len(exports.get("export_kinds", {}))
    
    # 重定位统计
    if "relocations" in arch_info and not isinstance(arch_info["relocations"], str):
        relocations = arch_info["relocations"]
        stats["total_relocations"] = relocations.get("total_relocations", 0)
        stats["relocation_types_count"] = len(relocations.get("relocation_types", {}))
    
    # 操作码可用性
    if "opcodes" in arch_info and not isinstance(arch_info["opcodes"], str):
        opcodes = arch_info["opcodes"]
        stats["opcodes_available"] = {
            "rebase_opcodes": "rebase_opcodes" in opcodes and opcodes["rebase_opcodes"] != "不可用",
            "bind_opcodes": "bind_opcodes" in opcodes and opcodes["bind_opcodes"] != "不可用",
            "export_trie": "export_trie" in opcodes and opcodes["export_trie"] != "不可用"
        }
    
    return stats
