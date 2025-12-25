"""
Mach-O 导出符号信息列表工具

此工具专门用于列出 Mach-O 文件中的所有导出符号信息，包括导出符号名称、地址、标志、类型等详细信息。
提供完整的导出符号解析，帮助理解二进制文件的对外接口和可用符号。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
from .common import compile_regex_filter, paginate_items, parse_macho, validate_file_path


def list_macho_exports(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    offset: Annotated[int, Field(
        description="起始位置偏移量，从第几个导出符号开始返回（从0开始计数）",
        ge=0
    )] = 0,
    count: Annotated[int, Field(
        description="返回的导出符号数量，最大100条，0表示返回所有剩余导出符号",
        ge=0,
        le=100
    )] = 20,
    name_filter: Annotated[Optional[str], Field(
        description="导出符号名称过滤器，支持正则表达式匹配。例如：'main' 或 '^_.*' 或 '.*malloc.*'"
    )] = None,
    include_details: Annotated[bool, Field(
        description="是否包含详细的导出信息分析"
    )] = True
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有导出符号信息，包括符号名称、地址、标志、类型等详细数据。
    
    该工具解析 Mach-O 文件的导出符号结构，提供：
    - 导出符号名称和去混淆名称
    - 导出地址和偏移信息
    - 导出标志和类型
    - 导出符号的用途分析
    - 导出统计和分类信息
    
    支持单架构和 Fat Binary 文件的导出符号信息提取。
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
        
        # 遍历所有架构的导出符号信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_exports = _extract_exports_info(binary, i, offset, count, name_filter, include_details)
                result["architectures"].append(arch_exports)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 导出符号信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件导出符号信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_exports_info(
    binary: lief.MachO.Binary, 
    index: int, 
    offset: int = 0, 
    count: int = 20, 
    name_filter: Optional[str] = None,
    include_details: bool = True
) -> Dict[str, Any]:
    """提取单个架构的导出符号详细信息，支持分页和过滤"""
    
    header = binary.header
    
    # 编译正则表达式过滤器
    regex_filter, filter_error = compile_regex_filter(name_filter)
    if filter_error:
        filter_error["architecture_index"] = index
        return filter_error
    
    # 收集所有导出符号信息
    all_exports = []
    total_exports_count = 0
    
    # 从导出符号中收集信息
    for export_symbol in binary.exported_symbols:
        total_exports_count += 1
        try:
            symbol_name = getattr(export_symbol, 'name', '')
            
            # 应用名称过滤器
            if regex_filter and not regex_filter.search(symbol_name):
                continue
            
            export_info = _extract_single_export_info(export_symbol, include_details)
            all_exports.append(export_info)
            
        except Exception as e:
            # 即使解析失败，也要检查是否符合过滤条件
            symbol_name = getattr(export_symbol, 'name', 'unknown')
            if not regex_filter or regex_filter.search(symbol_name):
                all_exports.append({
                    "name": symbol_name,
                    "error": f"解析导出符号信息时发生错误: {str(e)}"
                })
    
    filtered_count = len(all_exports)
    paged_exports, pagination_info, pagination_error = paginate_items(all_exports, offset, count)
    if pagination_error:
        pagination_error.update({
            "architecture_index": index,
            "cpu_type": str(header.cpu_type),
            "cpu_subtype": str(header.cpu_subtype),
        })
        return pagination_error
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "pagination_info": {
            "total_exports_in_binary": total_exports_count,
            "filtered_exports_count": filtered_count,
            "requested_offset": offset,
            "requested_count": count,
            "returned_count": pagination_info["returned_count"],
            "has_more": pagination_info["has_more"],
            "next_offset": pagination_info["next_offset"]
        },
        "filter_info": {
            "name_filter": name_filter,
            "filter_applied": name_filter is not None,
            "filter_valid": regex_filter is not None
        },
        "exports": paged_exports
    }
    
    # 添加导出符号统计信息（基于所有过滤后的导出符号，不仅仅是当前页）
    if include_details:
        arch_info["export_statistics"] = _calculate_export_statistics(all_exports)
    
    return arch_info


def _extract_single_export_info(export_symbol, include_details: bool = True) -> Dict[str, Any]:
    """提取单个导出符号的详细信息"""
    
    # 获取地址信息，优先从 export_info 获取，否则从 value 属性获取
    address_value = 0
    if hasattr(export_symbol, 'has_export_info') and export_symbol.has_export_info:
        try:
            address_value = export_symbol.export_info.address
        except Exception:
            pass
    
    # 如果没有 export_info，尝试从 value 属性获取
    if address_value == 0 and hasattr(export_symbol, 'value'):
        try:
            address_value = export_symbol.value
        except Exception:
            pass
    
    export_info = {
        "name": export_symbol.name,
        "demangled_name": getattr(export_symbol, 'demangled_name', export_symbol.name),
        "address": {
            "value": address_value,
            "hex": hex(address_value)
        }
    }
    
    # 添加导出信息详情
    if hasattr(export_symbol, 'has_export_info') and export_symbol.has_export_info:
        try:
            exp_info = export_symbol.export_info
            export_info["export_info"] = {
                "address": exp_info.address,
                "flags": {
                    "value": exp_info.flags,
                    "hex": hex(exp_info.flags),
                    "parsed_flags": _parse_export_flags(exp_info.flags) if include_details else []
                },
                "kind": {
                    "value": str(exp_info.kind),
                    "description": _get_export_kind_description(str(exp_info.kind))
                },
                "node_offset": exp_info.node_offset
            }
            
            # 添加其他字段（如果存在）
            if hasattr(exp_info, 'other'):
                export_info["export_info"]["other"] = exp_info.other
            
            if hasattr(exp_info, 'symbol'):
                try:
                    symbol = exp_info.symbol
                    export_info["export_info"]["symbol"] = {
                        "name": symbol.name,
                        "value": symbol.value,
                        "type": str(symbol.type)
                    }
                except Exception:
                    export_info["export_info"]["symbol"] = {"error": "无法获取符号信息"}
            
        except Exception as e:
            export_info["export_info"] = {"error": f"无法获取导出信息: {str(e)}"}
    
    # 添加符号类型信息
    if hasattr(export_symbol, 'type'):
        export_info["type"] = {
            "value": str(export_symbol.type),
            "description": _get_symbol_type_description(str(export_symbol.type))
        }
    
    # 添加符号分类信息
    if hasattr(export_symbol, 'category'):
        export_info["category"] = {
            "value": str(export_symbol.category),
            "description": _get_symbol_category_description(str(export_symbol.category))
        }
    
    # 添加符号来源信息
    if hasattr(export_symbol, 'origin'):
        export_info["origin"] = {
            "value": str(export_symbol.origin),
            "description": _get_symbol_origin_description(str(export_symbol.origin))
        }
    
    # 添加值信息
    if hasattr(export_symbol, 'value'):
        export_info["value"] = {
            "address": export_symbol.value,
            "hex": hex(export_symbol.value)
        }
    
    # 添加外部符号标志
    if hasattr(export_symbol, 'is_external'):
        export_info["is_external"] = export_symbol.is_external
    
    # 添加符号分析
    if include_details:
        export_info["symbol_analysis"] = _analyze_export_symbol_purpose(
            export_symbol.name, 
            str(getattr(export_symbol, 'type', 'UNKNOWN')),
            str(getattr(export_symbol, 'category', 'UNKNOWN'))
        )
    
    return export_info


def _parse_export_flags(flags: int) -> List[Dict[str, Any]]:
    """解析导出标志位"""
    
    # Mach-O 导出标志位定义
    flag_definitions = [
        (0x00, "EXPORT_SYMBOL_FLAGS_KIND_REGULAR", "常规导出符号"),
        (0x01, "EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL", "线程本地存储符号"),
        (0x02, "EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE", "绝对地址符号"),
        (0x04, "EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION", "弱定义符号"),
        (0x08, "EXPORT_SYMBOL_FLAGS_REEXPORT", "重新导出符号"),
        (0x10, "EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER", "存根和解析器")
    ]
    
    parsed_flags = []
    
    # 检查符号类型（低3位）
    kind = flags & 0x03
    for flag_value, flag_name, desc in flag_definitions[:3]:
        if kind == flag_value:
            parsed_flags.append({
                "flag": flag_name,
                "value": hex(flag_value),
                "description": desc
            })
            break
    
    # 检查其他标志位
    for flag_value, flag_name, desc in flag_definitions[3:]:
        if flags & flag_value:
            parsed_flags.append({
                "flag": flag_name,
                "value": hex(flag_value),
                "description": desc
            })
    
    return parsed_flags


def _get_export_kind_description(kind: str) -> str:
    """获取导出类型的描述"""
    
    kind_descriptions = {
        "REGULAR": "常规导出符号",
        "THREAD_LOCAL": "线程本地存储符号",
        "ABSOLUTE": "绝对地址符号"
    }
    
    return kind_descriptions.get(kind, f"未知导出类型: {kind}")


def _get_symbol_type_description(symbol_type: str) -> str:
    """获取符号类型的描述"""
    
    type_descriptions = {
        "UNDEFINED": "未定义符号，需要从其他模块解析",
        "ABSOLUTE_SYM": "绝对符号，值不会因重定位而改变",
        "SECTION": "节符号，定义在某个节中",
        "PREBOUND": "预绑定符号，已经预先绑定到特定地址",
        "INDIRECT": "间接符号，通过符号存根访问"
    }
    
    return type_descriptions.get(symbol_type, f"未知符号类型: {symbol_type}")


def _get_symbol_category_description(category: str) -> str:
    """获取符号分类的描述"""
    
    category_descriptions = {
        "NONE": "无特定分类",
        "LOCAL": "本地符号，仅在当前模块内可见",
        "EXTERNAL": "外部符号，可被其他模块引用",
        "UNDEFINED": "未定义符号，需要从其他模块解析",
        "INDIRECT_ABS": "间接绝对符号",
        "INDIRECT_LOCAL": "间接本地符号",
        "INDIRECT_ABS_LOCAL": "间接绝对本地符号"
    }
    
    return category_descriptions.get(category, f"未知符号分类: {category}")


def _get_symbol_origin_description(origin: str) -> str:
    """获取符号来源的描述"""
    
    origin_descriptions = {
        "UNKNOWN": "未知来源",
        "DYLD_EXPORT": "来自 Dyld 导出表",
        "DYLD_BIND": "来自 Dyld 绑定表",
        "SYMTAB": "来自符号表命令 (LC_SYMTAB)"
    }
    
    return origin_descriptions.get(origin, f"未知符号来源: {origin}")


def _analyze_export_symbol_purpose(symbol_name: str, symbol_type: str, category: str) -> Dict[str, Any]:
    """分析导出符号的用途和特性"""
    
    # 基于符号名称的分析
    analysis = {
        "purpose": "未知用途",
        "characteristics": [],
        "likely_usage": "常规导出符号",
        "api_category": "未分类"
    }
    
    name_lower = symbol_name.lower()
    
    # 系统和库函数
    if symbol_name.startswith('_'):
        analysis["characteristics"].append("C符号（下划线前缀）")
        
        # 常见系统函数
        if any(func in name_lower for func in ['malloc', 'free', 'printf', 'scanf', 'strlen', 'strcpy', 'memcpy']):
            analysis["purpose"] = "C标准库函数"
            analysis["likely_usage"] = "内存管理或字符串操作"
            analysis["api_category"] = "系统API"
        elif any(func in name_lower for func in ['objc_', 'class_', 'sel_']):
            analysis["purpose"] = "Objective-C运行时函数"
            analysis["likely_usage"] = "Objective-C对象和消息传递"
            analysis["api_category"] = "运行时API"
        elif 'main' in name_lower:
            analysis["purpose"] = "程序入口点"
            analysis["likely_usage"] = "程序执行起始点"
            analysis["api_category"] = "程序入口"
        elif any(func in name_lower for func in ['init', 'initialize']):
            analysis["purpose"] = "初始化函数"
            analysis["likely_usage"] = "模块或对象初始化"
            analysis["api_category"] = "初始化API"
        elif any(func in name_lower for func in ['cleanup', 'destroy', 'dealloc']):
            analysis["purpose"] = "清理函数"
            analysis["likely_usage"] = "资源清理和释放"
            analysis["api_category"] = "清理API"
    
    # Swift 符号
    elif symbol_name.startswith('$s') or symbol_name.startswith('_$s'):
        analysis["purpose"] = "Swift符号"
        analysis["characteristics"].append("Swift编译器生成")
        analysis["likely_usage"] = "Swift代码实现"
        analysis["api_category"] = "Swift API"
    
    # C++ 符号
    elif symbol_name.startswith('__Z') or symbol_name.startswith('_Z'):
        analysis["purpose"] = "C++混淆符号"
        analysis["characteristics"].append("C++编译器生成")
        analysis["likely_usage"] = "C++函数或方法"
        analysis["api_category"] = "C++ API"
    
    # 特殊符号
    elif symbol_name.startswith('GCC_'):
        analysis["purpose"] = "GCC编译器符号"
        analysis["characteristics"].append("编译器内部符号")
        analysis["api_category"] = "编译器符号"
    elif symbol_name.startswith('ltmp'):
        analysis["purpose"] = "临时标签符号"
        analysis["characteristics"].append("编译器生成的临时符号")
        analysis["api_category"] = "内部符号"
    elif symbol_name.startswith('L'):
        analysis["purpose"] = "本地标签"
        analysis["characteristics"].append("本地作用域符号")
        analysis["api_category"] = "内部符号"
    
    # 无前缀符号（通常是用户定义的公共API）
    else:
        analysis["purpose"] = "用户定义的公共API"
        analysis["characteristics"].append("公共接口符号")
        analysis["likely_usage"] = "对外提供的功能接口"
        analysis["api_category"] = "公共API"
    
    # 基于符号类型的分析
    if "SECTION" in symbol_type:
        analysis["characteristics"].append("定义在代码或数据节中")
    elif "ABSOLUTE_SYM" in symbol_type:
        analysis["characteristics"].append("绝对地址符号")
    
    # 基于分类的分析
    if "EXTERNAL" in category:
        analysis["characteristics"].append("可被其他模块访问")
        analysis["likely_usage"] += "，供外部调用"
    elif "LOCAL" in category:
        analysis["characteristics"].append("仅限当前模块内部使用")
    
    return analysis


def _calculate_export_statistics(exports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算导出符号统计信息"""
    
    stats = {
        "total_exports": len(exports),
        "exports_by_type": {},
        "exports_by_category": {},
        "exports_by_origin": {},
        "exports_by_api_category": {},
        "external_exports": 0,
        "local_exports": 0,
        "c_exports": 0,
        "swift_exports": 0,
        "cpp_exports": 0,
        "objc_exports": 0,
        "user_defined_exports": 0,
        "system_exports": 0,
        "regular_exports": 0,
        "weak_exports": 0,
        "thread_local_exports": 0,
        "absolute_exports": 0,
        "reexports": 0,
        "address_ranges": {
            "min_address": None,
            "max_address": None,
            "address_span": 0
        }
    }
    
    addresses = []
    
    for export in exports:
        if "error" in export:
            continue
        
        # 收集地址信息
        if "address" in export and "value" in export["address"]:
            addr = export["address"]["value"]
            if addr > 0:  # 忽略空地址
                addresses.append(addr)
        
        # 按类型统计
        if "type" in export:
            export_type = export["type"]["value"]
            stats["exports_by_type"][export_type] = stats["exports_by_type"].get(export_type, 0) + 1
        
        # 按分类统计
        if "category" in export:
            category = export["category"]["value"]
            stats["exports_by_category"][category] = stats["exports_by_category"].get(category, 0) + 1
            
            if "EXTERNAL" in category:
                stats["external_exports"] += 1
            elif "LOCAL" in category:
                stats["local_exports"] += 1
        
        # 按来源统计
        if "origin" in export:
            origin = export["origin"]["value"]
            stats["exports_by_origin"][origin] = stats["exports_by_origin"].get(origin, 0) + 1
        
        # 按API分类统计
        if "symbol_analysis" in export and "api_category" in export["symbol_analysis"]:
            api_category = export["symbol_analysis"]["api_category"]
            stats["exports_by_api_category"][api_category] = stats["exports_by_api_category"].get(api_category, 0) + 1
        
        # 按语言类型统计
        symbol_name = export.get("name", "")
        if symbol_name.startswith('_'):
            if any(x in symbol_name.lower() for x in ['objc_', 'class_', 'sel_']):
                stats["objc_exports"] += 1
            else:
                stats["c_exports"] += 1
        elif symbol_name.startswith('$s') or symbol_name.startswith('_$s'):
            stats["swift_exports"] += 1
        elif symbol_name.startswith('__Z') or symbol_name.startswith('_Z'):
            stats["cpp_exports"] += 1
        else:
            stats["user_defined_exports"] += 1
        
        # 系统 vs 用户符号
        if any(x in symbol_name for x in ['_', 'GCC_', 'ltmp', '__']):
            stats["system_exports"] += 1
        else:
            stats["user_defined_exports"] += 1
        
        # 导出标志统计
        if "export_info" in export and "flags" in export["export_info"]:
            flags = export["export_info"]["flags"]["value"]
            
            # 检查导出类型
            kind = flags & 0x03
            if kind == 0x00:
                stats["regular_exports"] += 1
            elif kind == 0x01:
                stats["thread_local_exports"] += 1
            elif kind == 0x02:
                stats["absolute_exports"] += 1
            
            # 检查其他标志
            if flags & 0x04:  # WEAK_DEFINITION
                stats["weak_exports"] += 1
            if flags & 0x08:  # REEXPORT
                stats["reexports"] += 1
    
    # 计算地址范围
    if addresses:
        stats["address_ranges"]["min_address"] = min(addresses)
        stats["address_ranges"]["max_address"] = max(addresses)
        stats["address_ranges"]["address_span"] = max(addresses) - min(addresses)
    
    return stats
