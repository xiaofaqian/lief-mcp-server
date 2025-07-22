"""
Mach-O 导入库和函数信息列表工具

此工具专门用于列出 Mach-O 文件中的所有导入库和函数信息，以简洁的表格格式显示：
索引|所在库|符号名|地址
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
    )] = None
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有导入库和函数信息，以简洁的表格格式显示。
    
    该工具解析 Mach-O 文件的导入结构，提供：
    - 导入符号名称和所属库
    - 符号地址信息
    - 简洁的表格格式输出：索引|库名|符号名|地址
    
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
            "architecture_count": len(fat_binary),
            "architectures": []
        }
        
        # 遍历所有架构的导入信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_imports = _extract_imports_info(binary, i, offset, count, name_filter)
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
    name_filter: Optional[str] = None
) -> Dict[str, Any]:
    """提取单个架构的导入信息，以简洁的表格格式返回"""
    
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
    
    # 收集所有导入信息
    all_imports = []
    
    try:
        # 建立库名映射
        library_map = {}
        for i, library in enumerate(binary.libraries):
            library_map[i] = _extract_library_name(library.name)
        
        # 收集导入符号信息
        for symbol in binary.imported_symbols:
            try:
                symbol_name = symbol.name
                
                # 应用名称过滤器
                if regex_filter and not regex_filter.search(symbol_name):
                    continue
                
                # 获取库名
                library_name = "unknown"
                if hasattr(symbol, 'library_ordinal') and symbol.library_ordinal > 0:
                    lib_index = symbol.library_ordinal - 1  # library_ordinal 从1开始
                    library_name = library_map.get(lib_index, "unknown")
                elif hasattr(symbol, 'has_library') and symbol.has_library:
                    try:
                        library_name = _extract_library_name(symbol.library.name)
                    except Exception:
                        library_name = "unknown"
                
                # 获取地址
                address = "0x0"
                if hasattr(symbol, 'has_binding_info') and symbol.has_binding_info:
                    try:
                        address = hex(symbol.binding_info.address)
                    except Exception:
                        pass
                elif hasattr(symbol, 'value') and symbol.value > 0:
                    address = hex(symbol.value)
                
                all_imports.append({
                    "symbol": symbol_name,
                    "library": library_name,
                    "address": address
                })
                
            except Exception as e:
                # 即使解析失败，也要检查是否符合过滤条件
                symbol_name = getattr(symbol, 'name', 'unknown')
                if not regex_filter or regex_filter.search(symbol_name):
                    all_imports.append({
                        "symbol": symbol_name,
                        "library": "error",
                        "address": "0x0"
                    })
        
        # 收集绑定信息中的额外符号
        for binding in binary.bindings:
            try:
                if not binding.has_symbol:
                    continue
                
                symbol_name = binding.symbol.name
                
                # 应用名称过滤器
                if regex_filter and not regex_filter.search(symbol_name):
                    continue
                
                # 检查是否已经存在
                if any(imp["symbol"] == symbol_name for imp in all_imports):
                    continue
                
                # 获取库名
                library_name = "unknown"
                if binding.has_library:
                    try:
                        library_name = _extract_library_name(binding.library.name)
                    except Exception:
                        library_name = "unknown"
                elif binding.library_ordinal > 0:
                    lib_index = binding.library_ordinal - 1
                    library_name = library_map.get(lib_index, "unknown")
                
                # 获取地址
                address = hex(binding.address) if binding.address > 0 else "0x0"
                
                all_imports.append({
                    "symbol": symbol_name,
                    "library": library_name,
                    "address": address
                })
                
            except Exception:
                continue
        
    except Exception as e:
        return {
            "architecture_index": index,
            "error": f"解析导入信息时发生错误: {str(e)}"
        }
    
    # 应用分页
    filtered_count = len(all_imports)
    
    # 检查偏移量是否有效
    if offset >= filtered_count and filtered_count > 0:
        return {
            "architecture_index": index,
            "cpu_type": str(header.cpu_type),
            "error": f"偏移量 {offset} 超出范围，过滤后的导入项总数为 {filtered_count}",
            "suggestion": f"请使用 0 到 {max(0, filtered_count - 1)} 之间的偏移量"
        }
    
    # 计算实际返回的导入项数量
    if count == 0:
        end_index = filtered_count
    else:
        end_index = min(offset + count, filtered_count)
    
    paged_imports = all_imports[offset:end_index]
    
    # 生成简洁的表格格式
    import_lines = []
    for i, import_item in enumerate(paged_imports, start=offset + 1):
        line = f"{i}|{import_item['library']}|{import_item['symbol']}|{import_item['address']}"
        import_lines.append(line)
    
    # 返回结果
    return {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "total_imports": filtered_count,
        "imports": import_lines,
        "pagination_info": {
            "offset": offset,
            "count": len(paged_imports),
            "has_more": end_index < filtered_count,
            "next_offset": end_index if end_index < filtered_count else None
        }
    }


def _extract_library_name(library_path: str) -> str:
    """从库路径中提取简洁的库名"""
    
    if not library_path:
        return "unknown"
    
    # 处理框架路径：/System/Library/Frameworks/Foundation.framework/Foundation -> Foundation
    if '.framework/' in library_path:
        parts = library_path.split('.framework/')
        if len(parts) >= 2:
            framework_name = parts[0].split('/')[-1]
            return framework_name
    
    # 处理普通库路径：/usr/lib/libSystem.B.dylib -> libSystem.B.dylib
    library_name = library_path.split('/')[-1]
    
    return library_name
