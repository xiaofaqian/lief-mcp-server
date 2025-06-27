"""
Mach-O方法引用查询工具

此工具用于查询Mach-O文件中指定方法地址的所有引用。
使用LIEF库的xref功能来分析二进制文件中的交叉引用。
"""

import lief
from typing import Annotated, List, Dict, Any
from pydantic import Field


def query_macho_method_references(
    file_path: Annotated[str, Field(description="Mach-O文件在系统中的完整绝对路径，例如：/Users/username/Documents/app.app/Contents/MacOS/app 或 /Applications/MyApp.app/Contents/MacOS/MyApp")],
    method_address: Annotated[str, Field(description="要查询引用的方法地址，支持十六进制格式（如0x1000）或十进制格式（如4096）")]
) -> Dict[str, Any]:
    """
    查询Mach-O文件中指定方法地址的所有引用
    
    此工具使用LIEF库的xref功能来查找所有引用指定地址的位置，
    并提供详细的引用分析信息，包括引用地址所在的段和节信息。
    
    Args:
        file_path: Mach-O文件的完整绝对路径
        method_address: 要查询引用的方法地址
        
    Returns:
        包含引用信息的字典，包括引用列表和详细分析
    """
    try:
        # 解析二进制文件
        binary = lief.parse(file_path)
        if binary is None:
            return {
                "success": False,
                "error": f"无法解析文件: {file_path}",
                "details": "文件可能不存在、损坏或不是有效的二进制文件"
            }
        
        # 检查是否为Mach-O格式
        if binary.format != lief.Binary.FORMATS.MACHO:
            return {
                "success": False,
                "error": "文件不是Mach-O格式",
                "details": f"检测到的格式: {binary.format}"
            }
        
        # 解析地址参数
        try:
            if method_address.startswith('0x') or method_address.startswith('0X'):
                target_address = int(method_address, 16)
            else:
                target_address = int(method_address)
        except ValueError:
            return {
                "success": False,
                "error": "无效的地址格式",
                "details": "地址必须是十进制数字或以0x开头的十六进制数字"
            }
        
        # 查询引用
        references = binary.xref(target_address)
        
        # 分析引用信息
        reference_details = []
        for ref_addr in references:
            ref_info = {
                "address": f"0x{ref_addr:x}",
                "decimal_address": ref_addr,
                "segment": None,
                "section": None,
                "offset_in_section": None
            }
            
            # 查找引用地址所在的段和节
            for segment in binary.segments:
                if segment.virtual_address <= ref_addr < segment.virtual_address + segment.virtual_size:
                    ref_info["segment"] = segment.name
                    
                    # 查找具体的节
                    for section in segment.sections:
                        section_start = section.virtual_address
                        section_end = section_start + section.size
                        if section_start <= ref_addr < section_end:
                            ref_info["section"] = section.name
                            ref_info["offset_in_section"] = ref_addr - section_start
                            break
                    break
            
            reference_details.append(ref_info)
        
        # 获取目标地址的信息
        target_info = {
            "address": f"0x{target_address:x}",
            "decimal_address": target_address,
            "segment": None,
            "section": None,
            "symbol": None
        }
        
        # 查找目标地址所在的段和节
        for segment in binary.segments:
            if segment.virtual_address <= target_address < segment.virtual_address + segment.virtual_size:
                target_info["segment"] = segment.name
                
                for section in segment.sections:
                    section_start = section.virtual_address
                    section_end = section_start + section.size
                    if section_start <= target_address < section_end:
                        target_info["section"] = section.name
                        break
                break
        
        # 查找目标地址的符号
        for symbol in binary.symbols:
            if hasattr(symbol, 'value') and symbol.value == target_address:
                target_info["symbol"] = symbol.name
                break
        
        return {
            "success": True,
            "file_path": file_path,
            "target_method": target_info,
            "reference_count": len(references),
            "references": reference_details,
            "summary": {
                "total_references": len(references),
                "segments_with_references": len(set(ref["segment"] for ref in reference_details if ref["segment"])),
                "sections_with_references": len(set(ref["section"] for ref in reference_details if ref["section"]))
            }
        }
        
    except FileNotFoundError:
        return {
            "success": False,
            "error": "文件未找到",
            "details": f"指定的文件路径不存在: {file_path}"
        }
    except PermissionError:
        return {
            "success": False,
            "error": "权限不足",
            "details": f"无法读取文件: {file_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": "处理过程中发生错误",
            "details": str(e)
        }
