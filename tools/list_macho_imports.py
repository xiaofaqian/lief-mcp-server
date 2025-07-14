"""
Mach-O 导入库和函数信息列表工具

此工具专门用于列出 Mach-O 文件中的所有导入库和函数信息，包括库依赖关系、导入符号、绑定信息等详细数据。
提供完整的导入分析，帮助理解二进制文件的外部依赖结构和动态链接配置。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os
import re


def list_macho_imports(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    offset: Annotated[int, Field(
        description="起始位置偏移量，从第几个导入项开始返回（从0开始计数）",
        ge=0
    )] = 0,
    count: Annotated[int, Field(
        description="返回的导入项数量，最大100条，0表示返回所有剩余导入项",
        ge=0,
        le=100
    )] = 20,
    name_filter: Annotated[Optional[str], Field(
        description="导入项名称过滤器，支持正则表达式匹配。例如：'malloc' 或 '^_.*' 或 '.*Foundation.*'"
    )] = None,
    include_libraries: Annotated[bool, Field(
        description="是否包含库依赖信息"
    )] = True,
    include_symbols: Annotated[bool, Field(
        description="是否包含导入符号信息"
    )] = True,
    include_bindings: Annotated[bool, Field(
        description="是否包含绑定信息"
    )] = True
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有导入库和函数信息，包括库依赖、导入符号、绑定信息等详细数据。
    
    该工具解析 Mach-O 文件的导入结构，提供：
    - 依赖库列表和版本信息
    - 导入符号名称和类型
    - 动态绑定信息和地址
    - 延迟绑定和弱绑定分析
    - 导入统计和依赖关系图
    
    支持单架构和 Fat Binary 文件的导入信息提取。
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
        
        # 遍历所有架构的导入信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_imports = _extract_imports_info(
                    binary, i, offset, count, name_filter,
                    include_libraries, include_symbols, include_bindings
                )
                result["architectures"].append(arch_imports)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 导入信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件导入信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_imports_info(
    binary: lief.MachO.Binary, 
    index: int, 
    offset: int = 0, 
    count: int = 20, 
    name_filter: Optional[str] = None,
    include_libraries: bool = True,
    include_symbols: bool = True,
    include_bindings: bool = True
) -> Dict[str, Any]:
    """提取单个架构的导入详细信息，支持分页和过滤"""
    
    header = binary.header
    
    # 编译正则表达式过滤器
    regex_filter = None
    if name_filter:
        try:
            regex_filter = re.compile(name_filter, re.IGNORECASE)
        except re.error as e:
            return {
                "architecture_index": index,
                "error": f"正则表达式过滤器无效: {name_filter}, 错误: {str(e)}",
                "suggestion": "请检查正则表达式语法，例如：'^_.*' 或 '.*malloc.*'"
            }
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "filter_info": {
            "name_filter": name_filter,
            "filter_applied": name_filter is not None,
            "filter_valid": regex_filter is not None
        }
    }
    
    # 收集所有导入信息
    all_imports = []
    
    # 1. 收集库依赖信息
    if include_libraries:
        try:
            libraries_info = _extract_libraries_info(binary, regex_filter)
            all_imports.extend(libraries_info)
        except Exception as e:
            arch_info["libraries_error"] = f"解析库依赖时发生错误: {str(e)}"
    
    # 2. 收集导入符号信息
    if include_symbols:
        try:
            symbols_info = _extract_imported_symbols_info(binary, regex_filter)
            all_imports.extend(symbols_info)
        except Exception as e:
            arch_info["symbols_error"] = f"解析导入符号时发生错误: {str(e)}"
    
    # 3. 收集绑定信息
    if include_bindings:
        try:
            bindings_info = _extract_bindings_info(binary, regex_filter)
            all_imports.extend(bindings_info)
        except Exception as e:
            arch_info["bindings_error"] = f"解析绑定信息时发生错误: {str(e)}"
    
    # 应用分页
    filtered_count = len(all_imports)
    
    # 检查偏移量是否有效
    if offset >= filtered_count and filtered_count > 0:
        arch_info.update({
            "error": f"偏移量 {offset} 超出范围，过滤后的导入项总数为 {filtered_count}",
            "suggestion": f"请使用 0 到 {max(0, filtered_count - 1)} 之间的偏移量"
        })
        return arch_info
    
    # 计算实际返回的导入项数量
    if count == 0:
        # 返回所有剩余导入项
        end_index = filtered_count
    else:
        end_index = min(offset + count, filtered_count)
    
    paged_imports = all_imports[offset:end_index]
    
    # 添加分页信息
    arch_info["pagination_info"] = {
        "total_imports": filtered_count,
        "requested_offset": offset,
        "requested_count": count,
        "returned_count": len(paged_imports),
        "has_more": end_index < filtered_count,
        "next_offset": end_index if end_index < filtered_count else None
    }
    
    # 添加导入项
    arch_info["imports"] = paged_imports
    
    # 添加导入统计信息（基于所有过滤后的导入项，不仅仅是当前页）
    arch_info["import_statistics"] = _calculate_import_statistics(all_imports)
    
    return arch_info


def _extract_libraries_info(binary: lief.MachO.Binary, regex_filter) -> List[Dict[str, Any]]:
    """提取库依赖信息"""
    
    libraries_info = []
    
    for library in binary.libraries:
        try:
            library_name = library.name
            
            # 应用名称过滤器
            if regex_filter and not regex_filter.search(library_name):
                continue
            
            lib_info = {
                "type": "library_dependency",
                "name": library_name,
                "current_version": library.current_version,
                "compatibility_version": library.compatibility_version,
                "timestamp": library.timestamp,
                "command_type": str(library.command),
                "details": {
                    "is_weak": "LOAD_WEAK_DYLIB" in str(library.command),
                    "is_reexport": "REEXPORT_DYLIB" in str(library.command),
                    "is_upward": "LOAD_UPWARD_DYLIB" in str(library.command),
                    "is_lazy": "LAZY_LOAD_DYLIB" in str(library.command)
                },
                "analysis": _analyze_library_purpose(library_name)
            }
            
            libraries_info.append(lib_info)
            
        except Exception as e:
            libraries_info.append({
                "type": "library_dependency",
                "name": getattr(library, 'name', 'unknown'),
                "error": f"解析库信息时发生错误: {str(e)}"
            })
    
    return libraries_info


def _extract_imported_symbols_info(binary: lief.MachO.Binary, regex_filter) -> List[Dict[str, Any]]:
    """提取导入符号信息"""
    
    symbols_info = []
    
    for symbol in binary.imported_symbols:
        try:
            symbol_name = symbol.name
            
            # 应用名称过滤器
            if regex_filter and not regex_filter.search(symbol_name):
                continue
            
            symbol_info = {
                "type": "imported_symbol",
                "name": symbol_name,
                "demangled_name": symbol.demangled_name if hasattr(symbol, 'demangled_name') else symbol_name,
                "symbol_type": {
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
                },
                "is_external": getattr(symbol, 'is_external', False),
                "library_ordinal": getattr(symbol, 'library_ordinal', 0)
            }
            
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
            symbol_info["analysis"] = _analyze_symbol_purpose(symbol_name, str(symbol.type), str(symbol.category))
            
            symbols_info.append(symbol_info)
            
        except Exception as e:
            symbols_info.append({
                "type": "imported_symbol",
                "name": getattr(symbol, 'name', 'unknown'),
                "error": f"解析符号信息时发生错误: {str(e)}"
            })
    
    return symbols_info


def _extract_bindings_info(binary: lief.MachO.Binary, regex_filter) -> List[Dict[str, Any]]:
    """提取绑定信息"""
    
    bindings_info = []
    
    for binding in binary.bindings:
        try:
            # 获取符号名称用于过滤
            symbol_name = ""
            if binding.has_symbol:
                symbol_name = binding.symbol.name
            
            # 应用名称过滤器
            if regex_filter and symbol_name and not regex_filter.search(symbol_name):
                continue
            
            binding_info = {
                "type": "binding_info",
                "address": binding.address,
                "addend": binding.addend,
                "library_ordinal": binding.library_ordinal,
                "weak_import": binding.weak_import
            }
            
            # 添加符号信息
            if binding.has_symbol:
                symbol = binding.symbol
                binding_info["symbol"] = {
                    "name": symbol.name,
                    "demangled_name": getattr(symbol, 'demangled_name', symbol.name),
                    "type": str(symbol.type),
                    "category": str(symbol.category)
                }
            
            # 添加库信息
            if binding.has_library:
                library = binding.library
                binding_info["library"] = {
                    "name": library.name,
                    "current_version": library.current_version,
                    "compatibility_version": library.compatibility_version
                }
            
            # 添加段信息
            if binding.has_segment:
                segment = binding.segment
                binding_info["segment"] = {
                    "name": segment.name,
                    "virtual_address": segment.virtual_address,
                    "file_offset": segment.file_offset
                }
            
            # 分析绑定类型（如果是 DyldBindingInfo）
            if hasattr(binding, 'binding_class'):
                binding_info["binding_class"] = {
                    "value": str(binding.binding_class),
                    "description": _get_binding_class_description(str(binding.binding_class))
                }
            
            if hasattr(binding, 'binding_type'):
                binding_info["binding_type"] = {
                    "value": str(binding.binding_type),
                    "description": _get_binding_type_description(str(binding.binding_type))
                }
            
            bindings_info.append(binding_info)
            
        except Exception as e:
            bindings_info.append({
                "type": "binding_info",
                "error": f"解析绑定信息时发生错误: {str(e)}"
            })
    
    return bindings_info


def _analyze_library_purpose(library_name: str) -> Dict[str, Any]:
    """分析库的用途和特性"""
    
    analysis = {
        "purpose": "未知用途",
        "category": "第三方库",
        "characteristics": [],
        "common_functions": []
    }
    
    name_lower = library_name.lower()
    
    # 系统库分析
    if library_name.startswith('/usr/lib/') or library_name.startswith('/System/'):
        analysis["category"] = "系统库"
        
        if 'libc' in name_lower or 'libsystem' in name_lower:
            analysis["purpose"] = "C标准库和系统调用"
            analysis["common_functions"] = ["malloc", "free", "printf", "open", "read", "write"]
        elif 'foundation' in name_lower:
            analysis["purpose"] = "Foundation框架 - Objective-C基础类"
            analysis["common_functions"] = ["NSString", "NSArray", "NSDictionary", "NSObject"]
        elif 'uikit' in name_lower:
            analysis["purpose"] = "UIKit框架 - iOS用户界面"
            analysis["common_functions"] = ["UIView", "UIViewController", "UIButton", "UILabel"]
        elif 'appkit' in name_lower:
            analysis["purpose"] = "AppKit框架 - macOS用户界面"
            analysis["common_functions"] = ["NSView", "NSViewController", "NSButton", "NSTextField"]
        elif 'corefoundation' in name_lower:
            analysis["purpose"] = "Core Foundation - C语言基础框架"
            analysis["common_functions"] = ["CFString", "CFArray", "CFDictionary"]
        elif 'security' in name_lower:
            analysis["purpose"] = "安全框架 - 加密和认证"
            analysis["common_functions"] = ["SecKeychain", "SecCertificate", "SecTrust"]
        elif 'network' in name_lower:
            analysis["purpose"] = "网络框架"
            analysis["common_functions"] = ["URLSession", "Socket", "HTTP"]
    
    # 特殊标记
    if library_name.endswith('.dylib'):
        analysis["characteristics"].append("动态链接库")
    if library_name.endswith('.framework'):
        analysis["characteristics"].append("框架")
    if '/Frameworks/' in library_name:
        analysis["characteristics"].append("系统框架")
    
    return analysis


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


def _calculate_import_statistics(imports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算导入统计信息"""
    
    stats = {
        "total_imports": len(imports),
        "imports_by_type": {},
        "libraries_count": 0,
        "symbols_count": 0,
        "bindings_count": 0,
        "weak_imports": 0,
        "lazy_bindings": 0,
        "system_libraries": 0,
        "third_party_libraries": 0,
        "c_symbols": 0,
        "swift_symbols": 0,
        "cpp_symbols": 0,
        "objc_symbols": 0,
        "top_libraries": {},
        "binding_classes": {},
        "symbol_origins": {}
    }
    
    for import_item in imports:
        if "error" in import_item:
            continue
        
        import_type = import_item.get("type", "unknown")
        stats["imports_by_type"][import_type] = stats["imports_by_type"].get(import_type, 0) + 1
        
        if import_type == "library_dependency":
            stats["libraries_count"] += 1
            
            # 统计系统库 vs 第三方库
            library_name = import_item.get("name", "")
            if library_name.startswith('/usr/lib/') or library_name.startswith('/System/'):
                stats["system_libraries"] += 1
            else:
                stats["third_party_libraries"] += 1
            
            # 统计顶级库
            stats["top_libraries"][library_name] = stats["top_libraries"].get(library_name, 0) + 1
            
            # 统计弱导入
            if import_item.get("details", {}).get("is_weak", False):
                stats["weak_imports"] += 1
        
        elif import_type == "imported_symbol":
            stats["symbols_count"] += 1
            
            # 按语言类型统计
            symbol_name = import_item.get("name", "")
            if symbol_name.startswith('_'):
                if any(x in symbol_name.lower() for x in ['objc_', 'class_', 'sel_']):
                    stats["objc_symbols"] += 1
                else:
                    stats["c_symbols"] += 1
            elif symbol_name.startswith('$s') or symbol_name.startswith('_$s'):
                stats["swift_symbols"] += 1
            elif symbol_name.startswith('__Z') or symbol_name.startswith('_Z'):
                stats["cpp_symbols"] += 1
            
            # 统计符号来源
            origin = import_item.get("origin", {}).get("value", "UNKNOWN")
            stats["symbol_origins"][origin] = stats["symbol_origins"].get(origin, 0) + 1
        
        elif import_type == "binding_info":
            stats["bindings_count"] += 1
            
            # 统计弱导入
            if import_item.get("weak_import", False):
                stats["weak_imports"] += 1
            
            # 统计绑定类别
            if "binding_class" in import_item:
                binding_class = import_item["binding_class"]["value"]
                stats["binding_classes"][binding_class] = stats["binding_classes"].get(binding_class, 0) + 1
                
                if binding_class == "LAZY":
                    stats["lazy_bindings"] += 1
    
    # 转换为列表格式以便显示
    stats["top_libraries"] = sorted(stats["top_libraries"].items(), key=lambda x: x[1], reverse=True)[:10]
    
    return stats
