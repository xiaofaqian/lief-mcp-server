"""
Mach-O Objective-C 元数据分析工具

此工具专门用于分析 Mach-O 文件中的 Objective-C 元数据信息，使用 LIEF 库直接解析二进制文件。
提供完整的 Objective-C 运行时信息解析，包括类、方法、协议、属性等详细信息。
支持分页和过滤机制，防止返回数据过大。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import os
import re
import lief


def analyze_macho_objc_metadata(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /System/Library/Frameworks/Foundation.framework/Foundation"
    )],
    offset: Annotated[int, Field(
        description="起始位置偏移量，从第几个类开始返回（从0开始计数）",
        ge=0
    )] = 0,
    count: Annotated[int, Field(
        description="返回的类数量，最大20条，0表示返回所有剩余类",
        ge=0,
        le=20
    )] = 5,
    class_filter: Annotated[Optional[str], Field(
        description="类名过滤器，支持正则表达式匹配。例如：'^NS.*' 或 '.*Controller$' 或 '.*View.*'"
    )] = None,
    method_filter: Annotated[Optional[str], Field(
        description="方法名过滤器，支持正则表达式匹配。例如：'init.*' 或 '.*delegate.*' 或 'set.*'"
    )] = None,
    summary_only: Annotated[bool, Field(
        description="是否只返回摘要信息（类名、方法数量、属性数量等），不包含详细内容"
    )] = False,
    include_methods: Annotated[bool, Field(
        description="是否包含方法详细信息（仅在summary_only=False时有效）"
    )] = False,
    include_properties: Annotated[bool, Field(
        description="是否包含属性详细信息（仅在summary_only=False时有效）"
    )] = False,
    include_protocols: Annotated[bool, Field(
        description="是否包含协议详细信息（仅在summary_only=False时有效）"
    )] = False,
    include_ivars: Annotated[bool, Field(
        description="是否包含实例变量详细信息（仅在summary_only=False时有效）"
    )] = False,
    generate_declarations: Annotated[bool, Field(
        description="是否生成类似 class-dump 的声明代码（仅在summary_only=False时有效）"
    )] = False,
    show_addresses: Annotated[bool, Field(
        description="是否显示内存地址信息（仅在summary_only=False时有效）"
    )] = False,
    architecture: Annotated[str, Field(
        description="指定架构类型，如 'x86_64'、'arm64' 等。如果不指定，将使用默认架构"
    )] = ""
) -> Dict[str, Any]:
    """
    使用 LIEF 分析 Mach-O 文件中的 Objective-C 元数据信息，包括类、方法、协议、属性等详细数据。
    
    该工具解析 Mach-O 文件的 Objective-C 运行时信息，提供：
    - 类的完整信息（名称、父类、实例大小等）
    - 方法列表（实例方法和类方法）
    - 属性列表和特性
    - 实例变量信息
    - 协议信息和继承关系
    - 类声明代码生成
    - 统计和分析信息
    
    使用 LIEF 库直接解析二进制文件，确保准确性和高效性。支持单架构和 Fat Binary 文件的 Objective-C 元数据提取。
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
        
        # 使用 LIEF 解析 Mach-O 文件
        macho_binary = _safe_parse_macho(file_path, architecture)
        if macho_binary is None:
            return {
                "error": f"无法解析 Mach-O 文件: {file_path}",
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        # 获取架构信息
        arch_info = _get_architecture_info(macho_binary)
        
        # 编译正则表达式过滤器
        class_regex_filter = None
        method_regex_filter = None
        
        if class_filter:
            try:
                class_regex_filter = re.compile(class_filter, re.IGNORECASE)
            except re.error as e:
                return {
                    "error": f"类名正则表达式过滤器无效: {class_filter}, 错误: {str(e)}",
                    "suggestion": "请检查正则表达式语法，例如：'^NS.*' 或 '.*Controller$'"
                }
        
        if method_filter:
            try:
                method_regex_filter = re.compile(method_filter, re.IGNORECASE)
            except re.error as e:
                return {
                    "error": f"方法名正则表达式过滤器无效: {method_filter}, 错误: {str(e)}",
                    "suggestion": "请检查正则表达式语法，例如：'init.*' 或 '.*delegate.*'"
                }
        
        # 分析 Objective-C 元数据
        objc_result = _analyze_objc_metadata_with_lief(
            macho_binary, offset, count,
            class_regex_filter, method_regex_filter, summary_only,
            include_methods, include_properties, include_protocols, 
            include_ivars, generate_declarations, show_addresses
        )
        
        # 构建完整结果
        result = {
            "file_path": file_path,
            "architecture_info": arch_info,
            "analysis_config": {
                "offset": offset,
                "count": count,
                "class_filter": class_filter,
                "method_filter": method_filter,
                "summary_only": summary_only,
                "include_methods": include_methods,
                "include_properties": include_properties,
                "include_protocols": include_protocols,
                "include_ivars": include_ivars,
                "generate_declarations": generate_declarations,
                "show_addresses": show_addresses
            }
        }
        
        result.update(objc_result)
        return result
        
    except Exception as e:
        return {
            "error": f"分析 Objective-C 元数据时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _safe_parse_macho(file_path: str, requested_arch: str = "") -> Optional[lief.MachO.Binary]:
    """安全解析 Mach-O 文件"""
    try:
        # 使用 LIEF 解析文件
        fat_binary = lief.MachO.parse(file_path)
        if fat_binary is None:
            return None
        
        # 处理 Fat Binary
        if len(fat_binary) > 1:
            # 如果指定了架构，尝试获取指定架构
            if requested_arch:
                # 尝试根据架构名称选择
                arch_mapping = {
                    'x86_64': lief.MachO.Header.CPU_TYPE.X86_64,
                    'arm64': lief.MachO.Header.CPU_TYPE.ARM64,
                    'i386': lief.MachO.Header.CPU_TYPE.X86,
                    'arm': lief.MachO.Header.CPU_TYPE.ARM
                }
                
                if requested_arch.lower() in arch_mapping:
                    selected_binary = fat_binary.take(arch_mapping[requested_arch.lower()])
                    if selected_binary:
                        return selected_binary
            
            # 默认选择第一个架构
            return fat_binary.at(0)
        else:
            return fat_binary.at(0)
            
    except Exception as e:
        return None


def _get_architecture_info(macho_binary: lief.MachO.Binary) -> Dict[str, Any]:
    """获取架构信息"""
    try:
        header = macho_binary.header
        
        # 获取 CPU 类型字符串
        cpu_type_str = str(header.cpu_type)
        cpu_subtype_str = str(header.cpu_subtype)
        
        # 提取架构名称
        arch_name = "unknown"
        if "X86_64" in cpu_type_str:
            arch_name = "x86_64"
        elif "ARM64" in cpu_type_str:
            arch_name = "arm64"
        elif "X86" in cpu_type_str and "X86_64" not in cpu_type_str:
            arch_name = "i386"
        elif "ARM" in cpu_type_str and "ARM64" not in cpu_type_str:
            arch_name = "arm"
        
        return {
            "selected_arch": arch_name,
            "cpu_type": cpu_type_str,
            "cpu_subtype": cpu_subtype_str,
            "file_type": str(header.file_type),
            "is_fat_binary": False  # 单个二进制文件
        }
        
    except Exception as e:
        return {
            "selected_arch": "unknown",
            "error": f"获取架构信息失败: {str(e)}"
        }


def _analyze_objc_metadata_with_lief(
    macho_binary: lief.MachO.Binary,
    offset: int,
    count: int,
    class_filter,
    method_filter,
    summary_only: bool,
    include_methods: bool,
    include_properties: bool,
    include_protocols: bool,
    include_ivars: bool,
    generate_declarations: bool,
    show_addresses: bool
) -> Dict[str, Any]:
    """使用 LIEF 分析 Objective-C 元数据"""
    
    try:
        # 获取 Objective-C 元数据
        metadata = macho_binary.objc_metadata
        
        if metadata is None:
            return {
                "has_objc_metadata": False,
                "message": "此文件不包含 Objective-C 元数据",
                "suggestion": "请检查文件是否包含 Objective-C 代码"
            }
        
        # 提取所有类信息
        all_classes = []
        for cls in metadata.classes:
            try:
                class_info = _extract_class_info(cls, show_addresses, include_methods, 
                                               include_properties, include_protocols, include_ivars)
                all_classes.append(class_info)
            except Exception as e:
                # 如果单个类解析失败，添加错误信息但继续处理其他类
                all_classes.append({
                    "name": "parse_error",
                    "error": f"解析类信息时发生错误: {str(e)}"
                })
        
        # 应用过滤器
        filtered_classes = _apply_filters(all_classes, class_filter, method_filter)
        
        # 应用分页
        total_classes = len(filtered_classes)
        
        if offset >= total_classes and total_classes > 0:
            return {
                "error": f"偏移量 {offset} 超出范围，过滤后的类总数为 {total_classes}",
                "suggestion": f"请使用 0 到 {max(0, total_classes - 1)} 之间的偏移量"
            }
        
        # 计算实际返回的类数量
        if count == 0:
            end_index = total_classes
        else:
            end_index = min(offset + count, total_classes)
        
        paged_classes = filtered_classes[offset:end_index]
        
        # 如果是摘要模式，简化类信息
        if summary_only:
            paged_classes = _create_class_summaries(paged_classes)
        else:
            # 根据参数过滤详细信息
            paged_classes = _filter_class_details(
                paged_classes, include_methods, include_properties, 
                include_protocols, include_ivars
            )
        
        # 构建结果
        result = {
            "has_objc_metadata": True,
            "summary_mode": summary_only,
            "pagination_info": {
                "total_classes_in_binary": len(all_classes),
                "filtered_classes_count": total_classes,
                "requested_offset": offset,
                "requested_count": count,
                "returned_count": len(paged_classes),
                "has_more": end_index < total_classes,
                "next_offset": end_index if end_index < total_classes else None
            },
            "filter_info": {
                "class_filter_applied": class_filter is not None,
                "method_filter_applied": method_filter is not None
            },
            "classes": paged_classes
        }
        
        # 生成声明代码（如果需要且不是摘要模式）
        if generate_declarations and not summary_only:
            result["declarations"] = _generate_lief_declarations(
                metadata, paged_classes, show_addresses
            )
        
        # 添加统计信息
        result["statistics"] = _calculate_statistics(all_classes)
        
        return result
        
    except Exception as e:
        return {
            "error": f"使用 LIEF 分析 Objective-C 元数据失败: {str(e)}",
            "suggestion": "请检查文件格式和 LIEF 库版本"
        }


def _extract_class_info(
    cls: lief.objc.Class, 
    show_addresses: bool,
    include_methods: bool,
    include_properties: bool,
    include_protocols: bool,
    include_ivars: bool
) -> Dict[str, Any]:
    """从 LIEF 类对象提取信息"""
    
    class_info = {
        "name": cls.name if hasattr(cls, 'name') else "unknown"
    }
    
    # 提取父类信息
    try:
        if hasattr(cls, 'super_class') and cls.super_class:
            class_info["superclass"] = {"name": cls.super_class.name}
        else:
            class_info["superclass"] = None
    except Exception:
        class_info["superclass"] = None
    
    # 提取实例大小（如果可用）
    try:
        if hasattr(cls, 'instance_size'):
            class_info["instance_size"] = cls.instance_size
    except Exception:
        pass
    
    # 提取方法信息
    if include_methods or not include_methods:  # 总是提取，后续根据参数决定是否包含
        class_info["methods"] = _extract_methods(cls, show_addresses)
    
    # 提取属性信息
    if include_properties or not include_properties:  # 总是提取，后续根据参数决定是否包含
        class_info["properties"] = _extract_properties(cls)
    
    # 提取实例变量信息
    if include_ivars or not include_ivars:  # 总是提取，后续根据参数决定是否包含
        class_info["instance_variables"] = _extract_ivars(cls)
    
    # 提取协议信息
    if include_protocols or not include_protocols:  # 总是提取，后续根据参数决定是否包含
        class_info["protocols"] = _extract_protocols(cls)
    
    return class_info


def _extract_methods(cls: lief.objc.Class, show_addresses: bool) -> Dict[str, List]:
    """提取方法信息"""
    
    instance_methods = []
    class_methods = []
    
    try:
        if hasattr(cls, 'methods'):
            for method in cls.methods:
                try:
                    method_info = {
                        "name": method.name if hasattr(method, 'name') else "unknown"
                    }
                    
                    # 添加地址信息（如果需要且可用）
                    if show_addresses and hasattr(method, 'address'):
                        try:
                            method_info["address"] = hex(method.address)
                            method_info["implementation"] = hex(method.address)
                        except Exception:
                            pass
                    
                    # 添加类型信息（如果可用）
                    if hasattr(method, 'types'):
                        try:
                            method_info["types"] = method.types
                        except Exception:
                            pass
                    
                    # 目前 LIEF 可能不区分实例方法和类方法，都放在实例方法中
                    instance_methods.append(method_info)
                    
                except Exception as e:
                    # 如果单个方法解析失败，添加错误信息
                    instance_methods.append({
                        "name": "method_parse_error",
                        "error": str(e)
                    })
    except Exception:
        pass
    
    return {
        "instance_methods": instance_methods,
        "class_methods": class_methods
    }


def _extract_properties(cls: lief.objc.Class) -> List[Dict[str, Any]]:
    """提取属性信息"""
    
    properties = []
    
    try:
        if hasattr(cls, 'properties'):
            for prop in cls.properties:
                try:
                    prop_info = {
                        "name": prop.name if hasattr(prop, 'name') else "unknown"
                    }
                    
                    # 添加属性特性（如果可用）
                    if hasattr(prop, 'attributes'):
                        try:
                            prop_info["attributes"] = prop.attributes
                        except Exception:
                            pass
                    
                    properties.append(prop_info)
                    
                except Exception as e:
                    properties.append({
                        "name": "property_parse_error",
                        "error": str(e)
                    })
    except Exception:
        pass
    
    return properties


def _extract_ivars(cls: lief.objc.Class) -> List[Dict[str, Any]]:
    """提取实例变量信息"""
    
    ivars = []
    
    try:
        if hasattr(cls, 'ivars'):
            for ivar in cls.ivars:
                try:
                    ivar_info = {
                        "name": ivar.name if hasattr(ivar, 'name') else "unknown"
                    }
                    
                    # 添加类型信息（如果可用）
                    if hasattr(ivar, 'type'):
                        try:
                            ivar_info["type"] = ivar.type
                        except Exception:
                            pass
                    
                    # 添加偏移信息（如果可用）
                    if hasattr(ivar, 'offset'):
                        try:
                            ivar_info["offset"] = ivar.offset
                        except Exception:
                            pass
                    
                    ivars.append(ivar_info)
                    
                except Exception as e:
                    ivars.append({
                        "name": "ivar_parse_error",
                        "error": str(e)
                    })
    except Exception:
        pass
    
    return ivars


def _extract_protocols(cls: lief.objc.Class) -> List[Dict[str, Any]]:
    """提取协议信息"""
    
    protocols = []
    
    try:
        if hasattr(cls, 'protocols'):
            for protocol in cls.protocols:
                try:
                    protocol_info = {
                        "name": protocol.name if hasattr(protocol, 'name') else "unknown"
                    }
                    
                    protocols.append(protocol_info)
                    
                except Exception as e:
                    protocols.append({
                        "name": "protocol_parse_error",
                        "error": str(e)
                    })
    except Exception:
        pass
    
    return protocols


def _apply_filters(classes: List[Dict[str, Any]], class_filter, method_filter) -> List[Dict[str, Any]]:
    """应用过滤器"""
    
    filtered_classes = []
    
    for cls in classes:
        if "error" in cls:
            filtered_classes.append(cls)
            continue
        
        class_name = cls.get("name", "")
        
        # 应用类名过滤器
        if class_filter and not class_filter.search(class_name):
            continue
        
        # 如果有方法过滤器，需要检查类的方法
        if method_filter:
            has_matching_method = False
            
            methods = cls.get("methods", {})
            for method_type in ["instance_methods", "class_methods"]:
                method_list = methods.get(method_type, [])
                for method in method_list:
                    method_name = method.get("name", "")
                    if method_filter.search(method_name):
                        has_matching_method = True
                        break
                
                if has_matching_method:
                    break
            
            if not has_matching_method:
                continue
        
        filtered_classes.append(cls)
    
    return filtered_classes


def _create_class_summaries(classes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """创建类的摘要信息，减少返回数据大小"""
    
    summaries = []
    
    for cls in classes:
        if "error" in cls:
            summaries.append(cls)
            continue
        
        # 统计各种元素的数量
        methods = cls.get("methods", {})
        instance_methods = methods.get("instance_methods", [])
        class_methods = methods.get("class_methods", [])
        properties = cls.get("properties", [])
        ivars = cls.get("instance_variables", [])
        protocols = cls.get("protocols", [])
        
        summary = {
            "name": cls.get("name", "unknown"),
            "superclass": cls.get("superclass", {}).get("name") if cls.get("superclass") else None,
            "instance_size": cls.get("instance_size"),
            "counts": {
                "instance_methods": len(instance_methods),
                "class_methods": len(class_methods),
                "total_methods": len(instance_methods) + len(class_methods),
                "properties": len(properties),
                "instance_variables": len(ivars),
                "protocols": len(protocols)
            }
        }
        
        # 如果有方法，只包含方法名列表（不包含详细信息）
        if instance_methods or class_methods:
            summary["method_names"] = {
                "instance_methods": [m.get("name", "unknown") for m in instance_methods],
                "class_methods": [m.get("name", "unknown") for m in class_methods]
            }
        
        # 如果有属性，只包含属性名列表
        if properties:
            summary["property_names"] = [p.get("name", "unknown") for p in properties]
        
        # 如果有实例变量，只包含变量名和类型
        if ivars:
            summary["ivar_names"] = [
                {"name": iv.get("name", "unknown"), "type": iv.get("type", "unknown")} 
                for iv in ivars
            ]
        
        # 如果有协议，只包含协议名
        if protocols:
            summary["protocol_names"] = [p.get("name", "unknown") for p in protocols]
        
        summaries.append(summary)
    
    return summaries


def _filter_class_details(
    classes: List[Dict[str, Any]], 
    include_methods: bool,
    include_properties: bool,
    include_protocols: bool,
    include_ivars: bool
) -> List[Dict[str, Any]]:
    """根据参数过滤类的详细信息"""
    
    filtered_classes = []
    
    for cls in classes:
        if "error" in cls:
            filtered_classes.append(cls)
            continue
        
        # 创建过滤后的类信息
        filtered_cls = {
            "name": cls.get("name"),
            "superclass": cls.get("superclass"),
            "instance_size": cls.get("instance_size")
        }
        
        # 根据参数决定是否包含详细信息
        if include_methods:
            filtered_cls["methods"] = cls.get("methods", {})
        else:
            # 只包含方法数量统计
            methods = cls.get("methods", {})
            instance_methods = methods.get("instance_methods", [])
            class_methods = methods.get("class_methods", [])
            filtered_cls["method_count"] = {
                "instance_methods": len(instance_methods),
                "class_methods": len(class_methods),
                "total": len(instance_methods) + len(class_methods)
            }
        
        if include_properties:
            filtered_cls["properties"] = cls.get("properties", [])
        else:
            properties = cls.get("properties", [])
            filtered_cls["property_count"] = len(properties)
        
        if include_protocols:
            filtered_cls["protocols"] = cls.get("protocols", [])
        else:
            protocols = cls.get("protocols", [])
            filtered_cls["protocol_count"] = len(protocols)
        
        if include_ivars:
            filtered_cls["instance_variables"] = cls.get("instance_variables", [])
        else:
            ivars = cls.get("instance_variables", [])
            filtered_cls["ivar_count"] = len(ivars)
        
        filtered_classes.append(filtered_cls)
    
    return filtered_classes


def _generate_lief_declarations(
    metadata: lief.objc.Metadata,
    classes: List[Dict[str, Any]], 
    show_addresses: bool
) -> Dict[str, Any]:
    """使用 LIEF 原生声明生成"""
    
    declarations = {
        "individual_classes": [],
        "full_declaration": ""
    }
    
    try:
        # 配置声明选项
        config = lief.objc.DeclOpt()
        config.show_annotations = show_addresses
        
        # 生成完整声明
        try:
            declarations["full_declaration"] = metadata.to_decl(config)
        except Exception as e:
            declarations["full_declaration"] = f"生成完整声明失败: {str(e)}"
        
        # 为每个类生成单独的声明
        for cls_info in classes:
            if "error" in cls_info:
                continue
            
            class_name = cls_info.get("name", "unknown")
            
            # 尝试从元数据中找到对应的类对象
            try:
                for cls in metadata.classes:
                    if hasattr(cls, 'name') and cls.name == class_name:
                        class_declaration = cls.to_decl(config)
                        declarations["individual_classes"].append({
                            "class_name": class_name,
                            "declaration": class_declaration
                        })
                        break
                else:
                    # 如果找不到对应的类，生成简单的声明
                    declarations["individual_classes"].append({
                        "class_name": class_name,
                        "declaration": f"// 无法为类 {class_name} 生成声明"
                    })
            except Exception as e:
                declarations["individual_classes"].append({
                    "class_name": class_name,
                    "declaration": f"// 生成类 {class_name} 声明失败: {str(e)}"
                })
        
    except Exception as e:
        declarations["error"] = f"生成声明失败: {str(e)}"
    
    return declarations


def _calculate_statistics(classes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算 Objective-C 统计信息"""
    
    stats = {
        "total_classes": len(classes),
        "classes_with_errors": 0,
        "classes_by_prefix": {},
        "classes_by_superclass": {},
        "total_methods": 0,
        "total_properties": 0,
        "total_instance_variables": 0,
        "average_methods_per_class": 0,
        "average_properties_per_class": 0,
        "classes_with_protocols": 0
    }
    
    total_methods = 0
    total_properties = 0
    total_ivars = 0
    classes_with_protocols = 0
    
    for cls in classes:
        if "error" in cls:
            stats["classes_with_errors"] += 1
            continue
        
        class_name = cls.get("name", "unknown")
        
        # 按前缀统计
        if len(class_name) >= 2:
            prefix = class_name[:2]
            stats["classes_by_prefix"][prefix] = stats["classes_by_prefix"].get(prefix, 0) + 1
        
        # 按父类统计
        superclass_name = cls.get("superclass", {}).get("name") if cls.get("superclass") else "NSObject"
        stats["classes_by_superclass"][superclass_name] = stats["classes_by_superclass"].get(superclass_name, 0) + 1
        
        # 统计方法数量
        methods = cls.get("methods", {})
        instance_methods = methods.get("instance_methods", [])
        class_methods = methods.get("class_methods", [])
        class_method_count = len(instance_methods) + len(class_methods)
        total_methods += class_method_count
        
        # 统计属性数量
        properties = cls.get("properties", [])
        class_property_count = len(properties)
        total_properties += class_property_count
        
        # 统计实例变量数量
        ivars = cls.get("instance_variables", [])
        total_ivars += len(ivars)
        
        # 统计有协议的类
        protocols = cls.get("protocols", [])
        if protocols:
            classes_with_protocols += 1
    
    # 计算平均值
    valid_classes = stats["total_classes"] - stats["classes_with_errors"]
    if valid_classes > 0:
        stats["average_methods_per_class"] = round(total_methods / valid_classes, 2)
        stats["average_properties_per_class"] = round(total_properties / valid_classes, 2)
    
    stats["total_methods"] = total_methods
    stats["total_properties"] = total_properties
    stats["total_instance_variables"] = total_ivars
    stats["classes_with_protocols"] = classes_with_protocols
    
    return stats
