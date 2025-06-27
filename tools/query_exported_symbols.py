"""
查询二进制文件导出符号的MCP工具
"""
from typing import Dict, Any, List, Annotated
from pydantic import Field
import lief
import re


def query_exported_symbols(
    file_path: Annotated[str, Field(
        description="二进制文件的完整路径，支持ELF、PE、MachO格式的可执行文件"
    )],
    symbol_name: Annotated[str, Field(
        description="要查询的符号名称，为空则返回所有导出符号"
    )] = "",
    use_regex: Annotated[bool, Field(
        description="是否使用正则表达式匹配符号名称"
    )] = False,
    limit: Annotated[int, Field(
        description="返回结果的最大数量，0表示无限制"
    )] = 100
) -> Dict[str, Any]:
    """
    查询二进制文件中的导出符号信息。
    
    此工具可以查询ELF、PE、MachO格式二进制文件中的导出符号，
    支持按名称精确匹配或正则表达式模糊匹配。返回符号的详细信息
    包括地址、类型、绑定信息等。
    
    支持的查询模式：
    - 查询所有导出符号（symbol_name为空）
    - 按符号名称精确查找
    - 按正则表达式模糊匹配
    """
    try:
        # 验证文件路径
        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "error": "无效的文件路径参数"
            }
        
        # 解析二进制文件
        binary = lief.parse(file_path)
        if binary is None:
            return {
                "success": False,
                "error": "无法解析文件，可能不是有效的二进制文件或格式不支持"
            }
        
        # 处理MachO FAT二进制文件
        if binary.format == lief.Binary.FORMATS.MACHO:
            # 如果是FAT二进制，取第一个架构
            if hasattr(binary, 'at') and callable(binary.at):
                binary = binary.at(0)
        
        # 获取导出符号
        symbols = _extract_exported_symbols(binary)
        
        # 过滤符号
        filtered_symbols = _filter_symbols(symbols, symbol_name, use_regex)
        
        # 限制结果数量
        if limit > 0:
            filtered_symbols = filtered_symbols[:limit]
        
        return {
            "success": True,
            "file_path": file_path,
            "format": binary.format.name,
            "total_symbols": len(symbols),
            "filtered_count": len(filtered_symbols),
            "query_info": {
                "symbol_name": symbol_name,
                "use_regex": use_regex,
                "limit": limit
            },
            "symbols": filtered_symbols
        }
        
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"文件不存在: {file_path}"
        }
    except PermissionError:
        return {
            "success": False,
            "error": f"没有权限访问文件: {file_path}"
        }
    except re.error as e:
        return {
            "success": False,
            "error": f"正则表达式错误: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"查询导出符号时发生错误: {str(e)}"
        }


def _extract_exported_symbols(binary) -> List[Dict[str, Any]]:
    """从二进制文件中提取导出符号"""
    symbols = []
    
    try:
        if binary.format == lief.Binary.FORMATS.ELF:
            symbols = _extract_elf_exported_symbols(binary)
        elif binary.format == lief.Binary.FORMATS.PE:
            symbols = _extract_pe_exported_symbols(binary)
        elif binary.format == lief.Binary.FORMATS.MACHO:
            symbols = _extract_macho_exported_symbols(binary)
        else:
            raise ValueError(f"不支持的二进制格式: {binary.format.name}")
            
    except Exception as e:
        raise Exception(f"提取{binary.format.name}导出符号失败: {str(e)}")
    
    return symbols


def _extract_elf_exported_symbols(binary) -> List[Dict[str, Any]]:
    """提取ELF格式的导出符号"""
    symbols = []
    
    try:
        # 获取导出符号
        for symbol in binary.exported_symbols:
            symbol_info = {
                "name": symbol.name,
                "address": hex(symbol.value) if symbol.value else "0x0",
                "type": symbol.type.name if hasattr(symbol.type, 'name') else str(symbol.type),
                "binding": symbol.binding.name if hasattr(symbol.binding, 'name') else str(symbol.binding),
                "visibility": symbol.visibility.name if hasattr(symbol.visibility, 'name') else str(symbol.visibility),
                "section": symbol.section.name if symbol.section else "未定义",
                "size": symbol.size
            }
            symbols.append(symbol_info)
            
    except Exception as e:
        raise Exception(f"ELF符号提取错误: {str(e)}")
    
    return symbols


def _extract_pe_exported_symbols(binary) -> List[Dict[str, Any]]:
    """提取PE格式的导出符号"""
    symbols = []
    
    try:
        # 获取导出表
        export_table = binary.get_export()
        if export_table:
            for entry in export_table.entries:
                symbol_info = {
                    "name": entry.name,
                    "address": hex(entry.address) if entry.address else "0x0",
                    "type": "函数" if entry.is_function else "数据",
                    "binding": "导出",
                    "visibility": "默认",
                    "section": "导出表",
                    "ordinal": entry.ordinal
                }
                symbols.append(symbol_info)
                
    except Exception as e:
        raise Exception(f"PE符号提取错误: {str(e)}")
    
    return symbols


def _extract_macho_exported_symbols(binary) -> List[Dict[str, Any]]:
    """提取MachO格式的导出符号"""
    symbols = []
    
    try:
        # 获取导出符号
        for symbol in binary.exported_symbols:
            symbol_info = {
                "name": symbol.name,
                "address": hex(symbol.value) if symbol.value else "0x0",
                "type": symbol.type.name if hasattr(symbol.type, 'name') else str(symbol.type),
                "binding": symbol.binding.name if hasattr(symbol.binding, 'name') else str(symbol.binding),
                "visibility": symbol.visibility.name if hasattr(symbol.visibility, 'name') else str(symbol.visibility),
                "section": symbol.section.name if symbol.section else "未定义",
                "description": symbol.description if hasattr(symbol, 'description') else ""
            }
            symbols.append(symbol_info)
            
    except Exception as e:
        raise Exception(f"MachO符号提取错误: {str(e)}")
    
    return symbols


def _filter_symbols(symbols: List[Dict[str, Any]], symbol_name: str, use_regex: bool) -> List[Dict[str, Any]]:
    """根据条件过滤符号"""
    if not symbol_name:
        return symbols
    
    filtered = []
    
    if use_regex:
        # 使用正则表达式匹配
        pattern = re.compile(symbol_name, re.IGNORECASE)
        for symbol in symbols:
            if pattern.search(symbol["name"]):
                filtered.append(symbol)
    else:
        # 精确匹配
        for symbol in symbols:
            if symbol["name"] == symbol_name:
                filtered.append(symbol)
    
    return filtered
