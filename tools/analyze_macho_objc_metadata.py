"""
Mach-O Objective-C 元数据分析工具

此工具专门用于分析 Mach-O 文件中的 Objective-C 元数据信息，使用 macOS 原生的 otool 工具。
提供完整的 Objective-C 运行时信息解析，包括类、方法、协议、属性等详细信息。
支持分页和过滤机制，防止返回数据过大。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import subprocess
import os
import re


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
    使用 otool 分析 Mach-O 文件中的 Objective-C 元数据信息，包括类、方法、协议、属性等详细数据。
    
    该工具解析 Mach-O 文件的 Objective-C 运行时信息，提供：
    - 类的完整信息（名称、父类、实例大小等）
    - 方法列表（实例方法和类方法）
    - 属性列表和特性
    - 实例变量信息
    - 协议信息和继承关系
    - 类声明代码生成
    - 统计和分析信息
    
    使用 macOS 原生 otool 工具，确保兼容性和准确性。支持单架构和 Fat Binary 文件的 Objective-C 元数据提取。
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
        
        # 检查 otool 工具是否可用
        if not _check_otool_available():
            return {
                "error": "otool 工具不可用",
                "suggestion": "此工具需要在 macOS 系统上运行，或安装 Xcode Command Line Tools"
            }
        
        # 获取文件架构信息
        arch_info = _get_architecture_info(file_path, architecture)
        if "error" in arch_info:
            return arch_info
        
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
        objc_result = _analyze_objc_metadata(
            file_path, arch_info["selected_arch"], offset, count,
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


def _check_otool_available() -> bool:
    """检查 otool 工具是否可用"""
    try:
        result = subprocess.run(['otool', '--version'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _get_architecture_info(file_path: str, requested_arch: str = "") -> Dict[str, Any]:
    """获取文件的架构信息"""
    try:
        # 使用 file 命令获取基本信息
        file_result = subprocess.run(['file', file_path], 
                                   capture_output=True, text=True, timeout=10)
        
        if file_result.returncode != 0:
            return {
                "error": f"无法获取文件信息: {file_result.stderr}",
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        file_output = file_result.stdout.strip()
        
        # 使用 lipo 命令获取架构列表（如果是 Fat Binary）
        lipo_result = subprocess.run(['lipo', '-info', file_path], 
                                   capture_output=True, text=True, timeout=10)
        
        architectures = []
        selected_arch = ""
        
        if lipo_result.returncode == 0:
            lipo_output = lipo_result.stdout.strip()
            
            if "Non-fat file" in lipo_output:
                # 单架构文件
                arch_match = re.search(r'is architecture: (\w+)', lipo_output)
                if arch_match:
                    arch = arch_match.group(1)
                    architectures = [arch]
                    selected_arch = arch
            else:
                # Fat Binary 文件
                arch_match = re.search(r'Architectures in the fat file: .* are: (.+)', lipo_output)
                if arch_match:
                    architectures = arch_match.group(1).split()
                    
                    # 选择架构
                    if requested_arch and requested_arch in architectures:
                        selected_arch = requested_arch
                    else:
                        selected_arch = architectures[0]  # 默认选择第一个
        
        if not architectures:
            return {
                "error": "无法识别文件架构",
                "file_info": file_output,
                "suggestion": "请确认文件是有效的 Mach-O 格式文件"
            }
        
        return {
            "file_type": file_output,
            "architectures": architectures,
            "selected_arch": selected_arch,
            "is_fat_binary": len(architectures) > 1
        }
        
    except subprocess.TimeoutExpired:
        return {
            "error": "获取架构信息超时",
            "suggestion": "文件可能过大或系统负载过高，请稍后重试"
        }
    except Exception as e:
        return {
            "error": f"获取架构信息失败: {str(e)}",
            "suggestion": "请检查文件是否为有效的 Mach-O 文件"
        }


def _analyze_objc_metadata(
    file_path: str,
    architecture: str,
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
    """使用 otool 分析 Objective-C 元数据"""
    
    try:
        # 使用 otool -oV 获取 Objective-C 元数据
        cmd = ['otool', '-oV', file_path]
        if architecture:
            cmd.extend(['-arch', architecture])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            return {
                "error": f"otool 执行失败: {result.stderr}",
                "command": ' '.join(cmd),
                "suggestion": "请检查文件是否包含 Objective-C 元数据，或尝试其他架构"
            }
        
        output = result.stdout
        
        # 检查是否包含 Objective-C 元数据
        if "Contents of (__DATA,__objc_classlist)" not in output and "Contents of (__DATA_CONST,__objc_classlist)" not in output:
            return {
                "has_objc_metadata": False,
                "message": "此文件不包含 Objective-C 元数据",
                "suggestion": "请检查文件是否包含 Objective-C 代码"
            }
        
        # 解析 Objective-C 元数据
        parsed_data = _parse_objc_output(output, show_addresses and not summary_only)
        
        # 应用过滤器
        filtered_classes = _apply_filters(parsed_data["classes"], class_filter, method_filter)
        
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
                "total_classes_in_binary": len(parsed_data["classes"]),
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
        
        # 添加协议信息（如果需要且不是摘要模式）
        if include_protocols and not summary_only:
            result["protocols"] = parsed_data.get("protocols", [])
        
        # 生成声明代码（如果需要且不是摘要模式）
        if generate_declarations and not summary_only:
            result["declarations"] = _generate_declarations(paged_classes)
        
        # 添加统计信息
        result["statistics"] = _calculate_statistics(parsed_data)
        
        return result
        
    except subprocess.TimeoutExpired:
        return {
            "error": "Objective-C 元数据分析超时",
            "suggestion": "文件可能过大，请尝试减少返回的类数量"
        }
    except Exception as e:
        return {
            "error": f"分析 Objective-C 元数据失败: {str(e)}",
            "suggestion": "请检查文件格式和权限"
        }


def _parse_objc_output(output: str, show_addresses: bool) -> Dict[str, Any]:
    """解析 otool -oV 的输出"""
    
    parsed_data = {
        "classes": [],
        "protocols": [],
        "categories": []
    }
    
    lines = output.split('\n')
    current_section = None
    current_class = None
    current_protocol = None
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # 识别不同的节
        if "Contents of (__DATA,__objc_classlist)" in line or "Contents of (__DATA_CONST,__objc_classlist)" in line:
            current_section = "classlist"
        elif "Contents of (__DATA,__objc_protolist)" in line or "Contents of (__DATA_CONST,__objc_protolist)" in line:
            current_section = "protolist"
        elif "Contents of (__DATA,__objc_catlist)" in line or "Contents of (__DATA_CONST,__objc_catlist)" in line:
            current_section = "catlist"
        elif line.startswith("isa ") and current_section == "classlist":
            # 开始解析一个新类
            current_class = _parse_class_info(lines, i, show_addresses)
            if current_class:
                parsed_data["classes"].append(current_class)
        elif line.startswith("isa ") and current_section == "protolist":
            # 开始解析一个新协议
            current_protocol = _parse_protocol_info(lines, i, show_addresses)
            if current_protocol:
                parsed_data["protocols"].append(current_protocol)
        
        i += 1
    
    return parsed_data


def _parse_class_info(lines: List[str], start_index: int, show_addresses: bool) -> Optional[Dict[str, Any]]:
    """解析单个类的信息"""
    
    class_info = {
        "name": "unknown",
        "superclass": None,
        "methods": {"instance_methods": [], "class_methods": []},
        "properties": [],
        "instance_variables": [],
        "protocols": []
    }
    
    i = start_index
    
    try:
        while i < len(lines):
            line = lines[i].strip()
            
            # 解析类名
            if "name " in line:
                name_match = re.search(r'name\s+(.+)', line)
                if name_match:
                    class_info["name"] = name_match.group(1).strip()
            
            # 解析父类
            elif "superclass " in line:
                superclass_match = re.search(r'superclass\s+(.+)', line)
                if superclass_match:
                    superclass_name = superclass_match.group(1).strip()
                    if superclass_name != "0x0":
                        class_info["superclass"] = {"name": superclass_name}
            
            # 解析实例大小
            elif "instance size " in line:
                size_match = re.search(r'instance size\s+(\d+)', line)
                if size_match:
                    class_info["instance_size"] = int(size_match.group(1))
            
            # 解析方法列表
            elif "baseMethods " in line:
                methods = _parse_method_list(lines, i + 1)
                class_info["methods"]["instance_methods"].extend(methods)
            
            # 解析属性列表
            elif "baseProperties " in line:
                properties = _parse_property_list(lines, i + 1)
                class_info["properties"].extend(properties)
            
            # 解析实例变量
            elif "ivars " in line:
                ivars = _parse_ivar_list(lines, i + 1)
                class_info["instance_variables"].extend(ivars)
            
            # 解析协议列表
            elif "baseProtocols " in line:
                protocols = _parse_protocol_list(lines, i + 1)
                class_info["protocols"].extend(protocols)
            
            # 检查是否到达下一个类或节的开始
            elif (line.startswith("isa ") or 
                  "Contents of" in line or 
                  line == ""):
                if i > start_index:  # 确保我们已经处理了一些内容
                    break
            
            i += 1
        
        return class_info if class_info["name"] != "unknown" else None
        
    except Exception as e:
        return {
            "name": "parse_error",
            "error": f"解析类信息时发生错误: {str(e)}"
        }


def _parse_method_list(lines: List[str], start_index: int) -> List[Dict[str, Any]]:
    """解析方法列表"""
    
    methods = []
    i = start_index
    
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith("isa ") or "Contents of" in line:
            break
        
        # 解析方法信息
        if "name " in line:
            method_info = {}
            
            # 提取方法名
            name_match = re.search(r'name\s+(.+)', line)
            if name_match:
                method_info["name"] = name_match.group(1).strip()
            
            # 查找类型和实现地址
            j = i + 1
            while j < len(lines) and j < i + 5:  # 限制搜索范围
                next_line = lines[j].strip()
                
                if "types " in next_line:
                    types_match = re.search(r'types\s+(.+)', next_line)
                    if types_match:
                        method_info["types"] = types_match.group(1).strip()
                
                elif "imp " in next_line:
                    imp_match = re.search(r'imp\s+(.+)', next_line)
                    if imp_match:
                        method_info["implementation"] = imp_match.group(1).strip()
                
                j += 1
            
            if "name" in method_info:
                methods.append(method_info)
        
        i += 1
    
    return methods


def _parse_property_list(lines: List[str], start_index: int) -> List[Dict[str, Any]]:
    """解析属性列表"""
    
    properties = []
    i = start_index
    
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith("isa ") or "Contents of" in line:
            break
        
        # 解析属性信息
        if "name " in line:
            prop_info = {}
            
            # 提取属性名
            name_match = re.search(r'name\s+(.+)', line)
            if name_match:
                prop_info["name"] = name_match.group(1).strip()
            
            # 查找属性特性
            j = i + 1
            while j < len(lines) and j < i + 3:
                next_line = lines[j].strip()
                
                if "attributes " in next_line:
                    attr_match = re.search(r'attributes\s+(.+)', next_line)
                    if attr_match:
                        prop_info["attributes"] = attr_match.group(1).strip()
                
                j += 1
            
            if "name" in prop_info:
                properties.append(prop_info)
        
        i += 1
    
    return properties


def _parse_ivar_list(lines: List[str], start_index: int) -> List[Dict[str, Any]]:
    """解析实例变量列表"""
    
    ivars = []
    i = start_index
    
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith("isa ") or "Contents of" in line:
            break
        
        # 解析实例变量信息
        if "name " in line:
            ivar_info = {}
            
            # 提取变量名
            name_match = re.search(r'name\s+(.+)', line)
            if name_match:
                ivar_info["name"] = name_match.group(1).strip()
            
            # 查找类型和偏移
            j = i + 1
            while j < len(lines) and j < i + 5:
                next_line = lines[j].strip()
                
                if "type " in next_line:
                    type_match = re.search(r'type\s+(.+)', next_line)
                    if type_match:
                        ivar_info["type"] = type_match.group(1).strip()
                
                elif "offset " in next_line:
                    offset_match = re.search(r'offset\s+(\d+)', next_line)
                    if offset_match:
                        ivar_info["offset"] = int(offset_match.group(1))
                
                j += 1
            
            if "name" in ivar_info:
                ivars.append(ivar_info)
        
        i += 1
    
    return ivars


def _parse_protocol_list(lines: List[str], start_index: int) -> List[Dict[str, Any]]:
    """解析协议列表"""
    
    protocols = []
    i = start_index
    
    while i < len(lines):
        line = lines[i].strip()
        
        if not line or line.startswith("isa ") or "Contents of" in line:
            break
        
        # 解析协议信息
        if "name " in line:
            protocol_info = {}
            
            # 提取协议名
            name_match = re.search(r'name\s+(.+)', line)
            if name_match:
                protocol_info["name"] = name_match.group(1).strip()
                protocols.append(protocol_info)
        
        i += 1
    
    return protocols


def _parse_protocol_info(lines: List[str], start_index: int, show_addresses: bool) -> Optional[Dict[str, Any]]:
    """解析协议信息"""
    
    protocol_info = {
        "name": "unknown",
        "methods": []
    }
    
    i = start_index
    
    try:
        while i < len(lines):
            line = lines[i].strip()
            
            # 解析协议名
            if "name " in line:
                name_match = re.search(r'name\s+(.+)', line)
                if name_match:
                    protocol_info["name"] = name_match.group(1).strip()
            
            # 解析方法列表
            elif "instanceMethods " in line or "classMethods " in line:
                methods = _parse_method_list(lines, i + 1)
                protocol_info["methods"].extend(methods)
            
            # 检查是否到达下一个协议或节的开始
            elif (line.startswith("isa ") or 
                  "Contents of" in line or 
                  line == ""):
                if i > start_index:
                    break
            
            i += 1
        
        return protocol_info if protocol_info["name"] != "unknown" else None
        
    except Exception as e:
        return {
            "name": "parse_error",
            "error": f"解析协议信息时发生错误: {str(e)}"
        }


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
            
            for method_type in ["instance_methods", "class_methods"]:
                methods = cls.get("methods", {}).get(method_type, [])
                for method in methods:
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


def _generate_declarations(classes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """生成类声明代码"""
    
    declarations = {
        "individual_classes": [],
        "full_declaration": ""
    }
    
    full_decl_lines = []
    
    for cls in classes:
        if "error" in cls:
            continue
        
        class_name = cls.get("name", "unknown")
        superclass = cls.get("superclass", {})
        superclass_name = superclass.get("name", "NSObject") if superclass else "NSObject"
        
        # 生成类声明
        class_decl_lines = []
        
        # 接口声明
        protocols = cls.get("protocols", [])
        protocol_str = ""
        if protocols:
            protocol_names = [p.get("name", "") for p in protocols if p.get("name")]
            if protocol_names:
                protocol_str = f" <{', '.join(protocol_names)}>"
        
        class_decl_lines.append(f"@interface {class_name} : {superclass_name}{protocol_str}")
        
        # 实例变量
        ivars = cls.get("instance_variables", [])
        if ivars:
            class_decl_lines.append("{")
            for ivar in ivars:
                ivar_name = ivar.get("name", "unknown")
                ivar_type = ivar.get("type", "id")
                class_decl_lines.append(f"    {ivar_type} {ivar_name};")
            class_decl_lines.append("}")
        
        # 属性
        properties = cls.get("properties", [])
        for prop in properties:
            prop_name = prop.get("name", "unknown")
            prop_attrs = prop.get("attributes", "")
            class_decl_lines.append(f"@property {prop_attrs} {prop_name};")
        
        # 方法
        methods = cls.get("methods", {})
        instance_methods = methods.get("instance_methods", [])
        class_methods = methods.get("class_methods", [])
        
        for method in class_methods:
            method_name = method.get("name", "unknown")
            method_types = method.get("types", "")
            class_decl_lines.append(f"+ {method_types} {method_name};")
        
        for method in instance_methods:
            method_name = method.get("name", "unknown")
            method_types = method.get("types", "")
            class_decl_lines.append(f"- {method_types} {method_name};")
        
        class_decl_lines.append("@end")
        class_decl_lines.append("")
        
        class_declaration = "\n".join(class_decl_lines)
        
        declarations["individual_classes"].append({
            "class_name": class_name,
            "declaration": class_declaration
        })
        
        full_decl_lines.extend(class_decl_lines)
    
    declarations["full_declaration"] = "\n".join(full_decl_lines)
    
    return declarations


def _calculate_statistics(parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    """计算 Objective-C 统计信息"""
    
    classes = parsed_data.get("classes", [])
    protocols = parsed_data.get("protocols", [])
    
    stats = {
        "total_classes": len(classes),
        "total_protocols": len(protocols),
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
        superclass = cls.get("superclass", {})
        if superclass:
            superclass_name = superclass.get("name", "unknown")
            stats["classes_by_superclass"][superclass_name] = stats["classes_by_superclass"].get(superclass_name, 0) + 1
        
        # 统计方法数量
        methods = cls.get("methods", {})
        instance_methods = methods.get("instance_methods", [])
        class_methods = methods.get("class_methods", [])
        class_method_count = len(instance_methods) + len(class_methods)
        total_methods += class_method_count
        
        # 统计属性数量
        properties = cls.get("properties", [])
        total_properties += len(properties)
        
        # 统计实例变量数量
        ivars = cls.get("instance_variables", [])
        total_ivars += len(ivars)
        
        # 统计协议数量
        protocols = cls.get("protocols", [])
        if protocols and len(protocols) > 0:
            classes_with_protocols += 1
    
    stats["total_methods"] = total_methods
    stats["total_properties"] = total_properties
    stats["total_instance_variables"] = total_ivars
    stats["classes_with_protocols"] = classes_with_protocols
    
    # 计算平均值
    valid_classes = stats["total_classes"] - stats["classes_with_errors"]
    if valid_classes > 0:
        stats["average_methods_per_class"] = round(total_methods / valid_classes, 2)
        stats["average_properties_per_class"] = round(total_properties / valid_classes, 2)
    
    return stats
