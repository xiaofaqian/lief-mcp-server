"""
Mach-O 符号表信息列表工具

此工具专门用于列出 Mach-O 文件中的所有符号信息，包括符号名称、类型、值、所属段等详细信息。
提供完整的符号表解析，帮助理解二进制文件的符号结构和符号组织方式。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
from .common import compile_regex_filter, paginate_items, parse_macho, validate_file_path


def list_macho_symbols(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    offset: Annotated[int, Field(
        description="起始位置偏移量，从第几个符号开始返回（从0开始计数）",
        ge=0
    )] = 0,
    count: Annotated[int, Field(
        description="返回的符号数量，最大100条，0表示返回所有剩余符号",
        ge=0,
        le=100
    )] = 20,
    name_filter: Annotated[Optional[str], Field(
        description="符号名称过滤器，支持正则表达式匹配。例如：'main' 或 '^_.*' 或 '.*malloc.*'"
    )] = None
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有符号信息，包括符号名称、类型、值、所属段等详细数据。
    
    该工具解析 Mach-O 文件的符号表结构，提供：
    - 符号名称和去混淆名称
    - 符号类型和分类
    - 符号值和地址信息
    - 符号来源（符号表、导出表、绑定表）
    - 符号所属库和段信息
    - 符号统计和分析
    
    支持单架构和 Fat Binary 文件的符号信息提取。
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
        
        # 遍历所有架构的符号信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_symbols = _extract_symbols_info(binary, i, offset, count, name_filter)
                result["architectures"].append(arch_symbols)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 符号信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件符号信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_symbols_info(binary: lief.MachO.Binary, index: int, offset: int = 0, count: int = 20, name_filter: Optional[str] = None) -> Dict[str, Any]:
    """提取单个架构的符号详细信息，支持分页和过滤"""
    
    header = binary.header
    
    # 编译正则表达式过滤器
    regex_filter, filter_error = compile_regex_filter(name_filter)
    if filter_error:
        filter_error["architecture_index"] = index
        return filter_error
    
    # 收集所有符号信息
    all_symbols = []
    total_symbols_count = 0
    
    for symbol in binary.symbols:
        total_symbols_count += 1
        try:
            symbol_name = getattr(symbol, 'name', '')
            
            # 应用名称过滤器
            if regex_filter and not regex_filter.search(symbol_name):
                continue
            
            symbol_info = _extract_single_symbol_info(symbol)
            all_symbols.append(symbol_info)
            
        except Exception as e:
            # 即使解析失败，也要检查是否符合过滤条件
            symbol_name = getattr(symbol, 'name', 'unknown')
            if not regex_filter or regex_filter.search(symbol_name):
                all_symbols.append({
                    "name": symbol_name,
                    "error": f"解析符号信息时发生错误: {str(e)}"
                })
    
    filtered_count = len(all_symbols)
    paged_symbols, pagination_info, pagination_error = paginate_items(all_symbols, offset, count)
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
            "total_symbols_in_binary": total_symbols_count,
            "filtered_symbols_count": filtered_count,
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
        "symbols": paged_symbols
    }
    
    # 添加符号统计信息（基于所有过滤后的符号，不仅仅是当前页）
    arch_info["symbol_statistics"] = _calculate_symbol_statistics(all_symbols)
    
    return arch_info


def _extract_single_symbol_info(symbol) -> Dict[str, Any]:
    """提取单个符号的详细信息"""
    
    symbol_info = {
        "name": symbol.name,
        "demangled_name": symbol.demangled_name if hasattr(symbol, 'demangled_name') else symbol.name,
        "value": {
            "address": symbol.value,
            "hex": hex(symbol.value)
        },
        "type": {
            "value": str(symbol.type),
            "description": _get_symbol_type_description(str(symbol.type))
        },
        "category": {
            "value": str(symbol.category),
            "description": _get_symbol_category_description(str(symbol.category))
        },
        "origin": {
            "value": str(symbol.origin),
            "description": _get_symbol_origin_description(str(symbol.origin))
        }
    }
    
    # 添加符号描述信息
    if hasattr(symbol, 'description'):
        try:
            desc_value = int(symbol.description)
            symbol_info["description"] = {
                "value": desc_value,
                "hex": hex(desc_value),
                "parsed_flags": _parse_symbol_description(desc_value)
            }
        except (TypeError, ValueError):
            symbol_info["description"] = {
                "value": str(symbol.description),
                "hex": "N/A",
                "parsed_flags": []
            }
    
    # 添加原始类型信息
    if hasattr(symbol, 'raw_type'):
        try:
            raw_type_value = int(symbol.raw_type)
            symbol_info["raw_type"] = {
                "value": raw_type_value,
                "hex": hex(raw_type_value),
                "parsed_type": _parse_raw_type(raw_type_value)
            }
        except (TypeError, ValueError):
            symbol_info["raw_type"] = {
                "value": str(symbol.raw_type),
                "hex": "N/A",
                "parsed_type": {}
            }
    
    # 添加外部符号信息
    if hasattr(symbol, 'is_external'):
        symbol_info["is_external"] = symbol.is_external
    
    # 添加库序号信息
    if hasattr(symbol, 'library_ordinal'):
        symbol_info["library_ordinal"] = symbol.library_ordinal
    
    # 添加节数量信息
    if hasattr(symbol, 'numberof_sections'):
        symbol_info["numberof_sections"] = symbol.numberof_sections
    
    # 添加关联的库信息
    if hasattr(symbol, 'has_library') and symbol.has_library:
        try:
            library = symbol.library
            symbol_info["library"] = {
                "name": library.name,
                "current_version": library.current_version,
                "compatibility_version": library.compatibility_version
            }
        except Exception:
            symbol_info["library"] = {"error": "无法获取库信息"}
    
    # 添加导出信息
    if hasattr(symbol, 'has_export_info') and symbol.has_export_info:
        try:
            export_info = symbol.export_info
            symbol_info["export_info"] = {
                "address": export_info.address,
                "flags": export_info.flags,
                "kind": str(export_info.kind),
                "node_offset": export_info.node_offset
            }
        except Exception:
            symbol_info["export_info"] = {"error": "无法获取导出信息"}
    
    # 添加绑定信息
    if hasattr(symbol, 'has_binding_info') and symbol.has_binding_info:
        try:
            binding_info = symbol.binding_info
            symbol_info["binding_info"] = {
                "address": binding_info.address,
                "addend": binding_info.addend,
                "library_ordinal": binding_info.library_ordinal,
                "weak_import": binding_info.weak_import
            }
        except Exception:
            symbol_info["binding_info"] = {"error": "无法获取绑定信息"}
    
    # 添加符号分析
    symbol_info["symbol_analysis"] = _analyze_symbol_purpose(symbol.name, str(symbol.type), str(symbol.category))
    
    return symbol_info


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


def _parse_symbol_description(description: int) -> List[Dict[str, Any]]:
    """解析符号描述标志位"""
    
    # Mach-O 符号描述标志位定义
    flag_definitions = [
        (0x0001, "REFERENCE_FLAG_UNDEFINED_NON_LAZY", "非延迟未定义引用"),
        (0x0002, "REFERENCE_FLAG_UNDEFINED_LAZY", "延迟未定义引用"),
        (0x0003, "REFERENCE_FLAG_DEFINED", "已定义符号"),
        (0x0004, "REFERENCE_FLAG_PRIVATE_DEFINED", "私有已定义符号"),
        (0x0005, "REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY", "私有非延迟未定义"),
        (0x0006, "REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY", "私有延迟未定义"),
        (0x0010, "REFERENCED_DYNAMICALLY", "动态引用"),
        (0x0020, "N_DESC_DISCARDED", "已丢弃"),
        (0x0040, "N_WEAK_REF", "弱引用"),
        (0x0080, "N_WEAK_DEF", "弱定义"),
        (0x0100, "N_REF_TO_WEAK", "引用弱符号"),
        (0x0200, "N_ARM_THUMB_DEF", "ARM Thumb 定义"),
        (0x0400, "N_SYMBOL_RESOLVER", "符号解析器"),
        (0x0800, "N_ALT_ENTRY", "替代入口点")
    ]
    
    parsed_flags = []
    
    # 检查引用类型（低4位）
    ref_type = description & 0x000F
    for flag_value, flag_name, desc in flag_definitions[:7]:
        if ref_type == flag_value:
            parsed_flags.append({
                "flag": flag_name,
                "value": hex(flag_value),
                "description": desc
            })
            break
    
    # 检查其他标志位
    for flag_value, flag_name, desc in flag_definitions[7:]:
        if description & flag_value:
            parsed_flags.append({
                "flag": flag_name,
                "value": hex(flag_value),
                "description": desc
            })
    
    return parsed_flags


def _parse_raw_type(raw_type: int) -> Dict[str, Any]:
    """解析原始符号类型"""
    
    # n_type 字段的组成
    n_stab = raw_type & 0xE0  # 调试符号类型
    n_pext = raw_type & 0x10  # 私有外部符号
    n_type = raw_type & 0x0E  # 符号类型
    n_ext = raw_type & 0x01   # 外部符号
    
    type_info = {
        "n_stab": {
            "value": n_stab,
            "hex": hex(n_stab),
            "description": "调试符号类型" if n_stab != 0 else "非调试符号"
        },
        "n_pext": {
            "value": bool(n_pext),
            "description": "私有外部符号" if n_pext else "非私有外部符号"
        },
        "n_type": {
            "value": n_type,
            "hex": hex(n_type),
            "description": _get_n_type_description(n_type)
        },
        "n_ext": {
            "value": bool(n_ext),
            "description": "外部符号" if n_ext else "本地符号"
        }
    }
    
    return type_info


def _get_n_type_description(n_type: int) -> str:
    """获取 n_type 字段的描述"""
    
    type_descriptions = {
        0x0: "N_UNDF - 未定义",
        0x2: "N_ABS - 绝对符号",
        0xE: "N_SECT - 节符号",
        0xC: "N_PBUD - 预绑定未定义",
        0xA: "N_INDR - 间接符号"
    }
    
    return type_descriptions.get(n_type, f"未知类型: {hex(n_type)}")


def _analyze_symbol_purpose(symbol_name: str, symbol_type: str, category: str) -> Dict[str, Any]:
    """分析符号的用途和特性"""
    
    # 基于符号名称的分析
    analysis = {
        "purpose": "未知用途",
        "characteristics": [],
        "likely_usage": "常规符号"
    }
    
    name_lower = symbol_name.lower()
    
    # 系统和库函数
    if symbol_name.startswith('_'):
        analysis["characteristics"].append("C符号（下划线前缀）")
        
        # 常见系统函数
        if any(func in name_lower for func in ['malloc', 'free', 'printf', 'scanf', 'strlen', 'strcpy', 'memcpy']):
            analysis["purpose"] = "C标准库函数"
            analysis["likely_usage"] = "内存管理或字符串操作"
        elif any(func in name_lower for func in ['objc_', 'class_', 'sel_']):
            analysis["purpose"] = "Objective-C运行时函数"
            analysis["likely_usage"] = "Objective-C对象和消息传递"
        elif 'main' in name_lower:
            analysis["purpose"] = "程序入口点"
            analysis["likely_usage"] = "程序执行起始点"
    
    # Swift 符号
    elif symbol_name.startswith('$s') or symbol_name.startswith('_$s'):
        analysis["purpose"] = "Swift符号"
        analysis["characteristics"].append("Swift编译器生成")
        analysis["likely_usage"] = "Swift代码实现"
    
    # C++ 符号
    elif symbol_name.startswith('__Z') or symbol_name.startswith('_Z'):
        analysis["purpose"] = "C++混淆符号"
        analysis["characteristics"].append("C++编译器生成")
        analysis["likely_usage"] = "C++函数或方法"
    
    # 特殊符号
    elif symbol_name.startswith('GCC_'):
        analysis["purpose"] = "GCC编译器符号"
        analysis["characteristics"].append("编译器内部符号")
    elif symbol_name.startswith('ltmp'):
        analysis["purpose"] = "临时标签符号"
        analysis["characteristics"].append("编译器生成的临时符号")
    elif symbol_name.startswith('L'):
        analysis["purpose"] = "本地标签"
        analysis["characteristics"].append("本地作用域符号")
    
    # 基于符号类型的分析
    if "UNDEFINED" in symbol_type:
        analysis["characteristics"].append("需要动态链接")
        analysis["likely_usage"] = "外部库函数调用"
    elif "SECTION" in symbol_type:
        analysis["characteristics"].append("定义在代码或数据节中")
    
    # 基于分类的分析
    if "EXTERNAL" in category:
        analysis["characteristics"].append("可被其他模块访问")
    elif "LOCAL" in category:
        analysis["characteristics"].append("仅限当前模块内部使用")
    
    return analysis


def _calculate_symbol_statistics(symbols: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算符号统计信息"""
    
    stats = {
        "total_symbols": len(symbols),
        "symbols_by_type": {},
        "symbols_by_category": {},
        "symbols_by_origin": {},
        "external_symbols": 0,
        "local_symbols": 0,
        "undefined_symbols": 0,
        "defined_symbols": 0,
        "c_symbols": 0,
        "swift_symbols": 0,
        "cpp_symbols": 0,
        "objc_symbols": 0,
        "system_symbols": 0,
        "user_symbols": 0
    }
    
    for symbol in symbols:
        if "error" in symbol:
            continue
        
        # 按类型统计
        if "type" in symbol:
            symbol_type = symbol["type"]["value"]
            stats["symbols_by_type"][symbol_type] = stats["symbols_by_type"].get(symbol_type, 0) + 1
        
        # 按分类统计
        if "category" in symbol:
            category = symbol["category"]["value"]
            stats["symbols_by_category"][category] = stats["symbols_by_category"].get(category, 0) + 1
            
            if "EXTERNAL" in category:
                stats["external_symbols"] += 1
            elif "LOCAL" in category:
                stats["local_symbols"] += 1
        
        # 按来源统计
        if "origin" in symbol:
            origin = symbol["origin"]["value"]
            stats["symbols_by_origin"][origin] = stats["symbols_by_origin"].get(origin, 0) + 1
        
        # 按定义状态统计
        if "type" in symbol:
            if "UNDEFINED" in symbol["type"]["value"]:
                stats["undefined_symbols"] += 1
            else:
                stats["defined_symbols"] += 1
        
        # 按语言类型统计
        symbol_name = symbol.get("name", "")
        if symbol_name.startswith('_'):
            if any(x in symbol_name.lower() for x in ['objc_', 'class_', 'sel_']):
                stats["objc_symbols"] += 1
            else:
                stats["c_symbols"] += 1
        elif symbol_name.startswith('$s') or symbol_name.startswith('_$s'):
            stats["swift_symbols"] += 1
        elif symbol_name.startswith('__Z') or symbol_name.startswith('_Z'):
            stats["cpp_symbols"] += 1
        
        # 系统 vs 用户符号
        if any(x in symbol_name for x in ['_', 'GCC_', 'ltmp', '__']):
            stats["system_symbols"] += 1
        else:
            stats["user_symbols"] += 1
    
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
