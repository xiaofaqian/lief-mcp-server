"""
Mach-O 重定位信息列表工具

此工具专门用于列出 Mach-O 文件中的所有重定位信息，包括重定位地址、类型、符号信息等详细数据。
提供完整的重定位表解析，帮助理解二进制文件的重定位结构和地址修正机制。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os
import re


def list_macho_relocations(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    offset: Annotated[int, Field(
        description="起始位置偏移量，从第几个重定位开始返回（从0开始计数）",
        ge=0
    )] = 0,
    count: Annotated[int, Field(
        description="返回的重定位数量，最大100条，0表示返回所有剩余重定位",
        ge=0,
        le=100
    )] = 20,
    address_filter: Annotated[Optional[str], Field(
        description="地址过滤器，支持十六进制地址范围。例如：'0x100000000-0x100001000' 或 '0x100000000+'"
    )] = None
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有重定位信息，包括重定位地址、类型、符号等详细数据。
    
    该工具解析 Mach-O 文件的重定位结构，提供：
    - 重定位地址和目标地址
    - 重定位类型和架构特定信息
    - 关联的符号信息
    - 重定位来源（rebase、bind等）
    - 重定位统计和分析
    
    支持单架构和 Fat Binary 文件的重定位信息提取。
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
        
        # 遍历所有架构的重定位信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_relocations = _extract_relocations_info(binary, i, offset, count, address_filter)
                result["architectures"].append(arch_relocations)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 重定位信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件重定位信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_relocations_info(binary: lief.MachO.Binary, index: int, offset: int = 0, count: int = 20, address_filter: Optional[str] = None) -> Dict[str, Any]:
    """提取单个架构的重定位详细信息，支持分页和过滤"""
    
    header = binary.header
    
    # 解析地址过滤器
    address_range = None
    if address_filter:
        try:
            address_range = _parse_address_filter(address_filter)
        except ValueError as e:
            return {
                "architecture_index": index,
                "error": f"地址过滤器无效: {address_filter}, 错误: {str(e)}",
                "suggestion": "请使用格式：'0x100000000-0x100001000' 或 '0x100000000+'"
            }
    
    # 收集所有重定位信息
    all_relocations = []
    total_relocations_count = 0
    
    # 获取重定位信息
    try:
        for relocation in binary.relocations:
            total_relocations_count += 1
            try:
                # 应用地址过滤器
                if address_range and not _address_in_range(relocation.address, address_range):
                    continue
                
                relocation_info = _extract_single_relocation_info(relocation)
                all_relocations.append(relocation_info)
                
            except Exception as e:
                # 即使解析失败，也要检查是否符合过滤条件
                reloc_address = getattr(relocation, 'address', 0)
                if not address_range or _address_in_range(reloc_address, address_range):
                    all_relocations.append({
                        "address": hex(reloc_address),
                        "error": f"解析重定位信息时发生错误: {str(e)}"
                    })
    except Exception as e:
        return {
            "architecture_index": index,
            "cpu_type": str(header.cpu_type),
            "cpu_subtype": str(header.cpu_subtype),
            "error": f"访问重定位信息时发生错误: {str(e)}",
            "suggestion": "该文件可能没有重定位信息或格式不支持"
        }
    
    # 应用分页
    filtered_count = len(all_relocations)
    
    # 检查偏移量是否有效
    if offset >= filtered_count and filtered_count > 0:
        return {
            "architecture_index": index,
            "cpu_type": str(header.cpu_type),
            "cpu_subtype": str(header.cpu_subtype),
            "error": f"偏移量 {offset} 超出范围，过滤后的重定位总数为 {filtered_count}",
            "suggestion": f"请使用 0 到 {max(0, filtered_count - 1)} 之间的偏移量"
        }
    
    # 计算实际返回的重定位数量
    if count == 0:
        # 返回所有剩余重定位
        end_index = filtered_count
    else:
        end_index = min(offset + count, filtered_count)
    
    paged_relocations = all_relocations[offset:end_index]
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "pagination_info": {
            "total_relocations_in_binary": total_relocations_count,
            "filtered_relocations_count": filtered_count,
            "requested_offset": offset,
            "requested_count": count,
            "returned_count": len(paged_relocations),
            "has_more": end_index < filtered_count,
            "next_offset": end_index if end_index < filtered_count else None
        },
        "filter_info": {
            "address_filter": address_filter,
            "filter_applied": address_filter is not None,
            "filter_valid": address_range is not None
        },
        "relocations": paged_relocations
    }
    
    # 添加重定位统计信息（基于所有过滤后的重定位，不仅仅是当前页）
    arch_info["relocation_statistics"] = _calculate_relocation_statistics(all_relocations)
    
    # 添加 DYLD 信息分析
    arch_info["dyld_info"] = _extract_dyld_relocation_info(binary)
    
    return arch_info


def _extract_single_relocation_info(relocation) -> Dict[str, Any]:
    """提取单个重定位的详细信息"""
    
    relocation_info = {
        "address": {
            "value": relocation.address,
            "hex": hex(relocation.address)
        }
    }
    
    # 添加重定位类型信息
    if hasattr(relocation, 'type'):
        try:
            reloc_type = str(relocation.type)
            relocation_info["type"] = {
                "value": reloc_type,
                "description": _get_relocation_type_description(reloc_type)
            }
        except Exception:
            relocation_info["type"] = {
                "value": "unknown",
                "description": "无法获取重定位类型"
            }
    
    # 添加架构特定信息
    if hasattr(relocation, 'architecture'):
        try:
            arch = str(relocation.architecture)
            relocation_info["architecture"] = {
                "value": arch,
                "description": _get_architecture_description(arch)
            }
        except Exception:
            relocation_info["architecture"] = {
                "value": "unknown",
                "description": "无法获取架构信息"
            }
    
    # 添加符号信息
    if hasattr(relocation, 'has_symbol') and relocation.has_symbol:
        try:
            symbol = relocation.symbol
            relocation_info["symbol"] = {
                "name": symbol.name,
                "demangled_name": getattr(symbol, 'demangled_name', symbol.name),
                "value": {
                    "address": symbol.value,
                    "hex": hex(symbol.value)
                },
                "type": str(symbol.type),
                "category": str(symbol.category)
            }
        except Exception as e:
            relocation_info["symbol"] = {
                "error": f"无法获取符号信息: {str(e)}"
            }
    
    # 添加段信息
    if hasattr(relocation, 'has_segment') and relocation.has_segment:
        try:
            segment = relocation.segment
            relocation_info["segment"] = {
                "name": segment.name,
                "virtual_address": {
                    "value": segment.virtual_address,
                    "hex": hex(segment.virtual_address)
                },
                "virtual_size": segment.virtual_size,
                "file_offset": segment.file_offset
            }
        except Exception as e:
            relocation_info["segment"] = {
                "error": f"无法获取段信息: {str(e)}"
            }
    
    # 添加节信息
    if hasattr(relocation, 'has_section') and relocation.has_section:
        try:
            section = relocation.section
            relocation_info["section"] = {
                "name": section.name,
                "virtual_address": {
                    "value": section.virtual_address,
                    "hex": hex(section.virtual_address)
                },
                "size": section.size,
                "offset": section.offset
            }
        except Exception as e:
            relocation_info["section"] = {
                "error": f"无法获取节信息: {str(e)}"
            }
    
    # 添加原始重定位信息
    if hasattr(relocation, 'origin'):
        try:
            origin = str(relocation.origin)
            relocation_info["origin"] = {
                "value": origin,
                "description": _get_relocation_origin_description(origin)
            }
        except Exception:
            relocation_info["origin"] = {
                "value": "unknown",
                "description": "无法获取重定位来源"
            }
    
    # 添加重定位分析
    relocation_info["relocation_analysis"] = _analyze_relocation_purpose(relocation_info)
    
    return relocation_info


def _parse_address_filter(address_filter: str) -> Dict[str, int]:
    """解析地址过滤器"""
    
    address_filter = address_filter.strip()
    
    if '-' in address_filter:
        # 地址范围：0x100000000-0x100001000
        parts = address_filter.split('-')
        if len(parts) != 2:
            raise ValueError("地址范围格式错误，应为：start-end")
        
        start_addr = int(parts[0].strip(), 0)
        end_addr = int(parts[1].strip(), 0)
        
        if start_addr >= end_addr:
            raise ValueError("起始地址必须小于结束地址")
        
        return {"start": start_addr, "end": end_addr, "type": "range"}
    
    elif address_filter.endswith('+'):
        # 起始地址：0x100000000+
        start_addr = int(address_filter[:-1].strip(), 0)
        return {"start": start_addr, "type": "from"}
    
    else:
        # 单个地址：0x100000000
        addr = int(address_filter, 0)
        return {"start": addr, "end": addr, "type": "exact"}


def _address_in_range(address: int, address_range: Dict[str, int]) -> bool:
    """检查地址是否在指定范围内"""
    
    if address_range["type"] == "range":
        return address_range["start"] <= address <= address_range["end"]
    elif address_range["type"] == "from":
        return address >= address_range["start"]
    elif address_range["type"] == "exact":
        return address == address_range["start"]
    
    return False


def _get_relocation_type_description(reloc_type: str) -> str:
    """获取重定位类型的描述"""
    
    type_descriptions = {
        "POINTER": "指针重定位，修正指针地址",
        "ABSOLUTE": "绝对地址重定位",
        "RELATIVE": "相对地址重定位",
        "BRANCH": "分支指令重定位",
        "GOT": "全局偏移表重定位",
        "PLT": "过程链接表重定位",
        "DYLDINFO": "DYLD 信息重定位",
        "REBASE": "重定基址重定位",
        "BIND": "符号绑定重定位",
        "LAZY_BIND": "延迟绑定重定位",
        "WEAK_BIND": "弱绑定重定位"
    }
    
    # 检查是否包含已知类型
    for known_type, description in type_descriptions.items():
        if known_type in reloc_type.upper():
            return description
    
    return f"未知重定位类型: {reloc_type}"


def _get_architecture_description(arch: str) -> str:
    """获取架构的描述"""
    
    arch_descriptions = {
        "X86": "Intel x86 32位架构",
        "X86_64": "Intel x86 64位架构",
        "ARM": "ARM 32位架构",
        "ARM64": "ARM 64位架构",
        "PPC": "PowerPC 架构",
        "PPC64": "PowerPC 64位架构"
    }
    
    return arch_descriptions.get(arch.upper(), f"架构: {arch}")


def _get_relocation_origin_description(origin: str) -> str:
    """获取重定位来源的描述"""
    
    origin_descriptions = {
        "UNKNOWN": "未知来源",
        "DYLDINFO": "来自 DYLD 信息",
        "LINKEDIT": "来自链接编辑数据",
        "SYMTAB": "来自符号表",
        "DYSYMTAB": "来自动态符号表",
        "REBASE": "来自重定基址信息",
        "BIND": "来自绑定信息",
        "WEAK_BIND": "来自弱绑定信息",
        "LAZY_BIND": "来自延迟绑定信息",
        "EXPORT": "来自导出信息"
    }
    
    return origin_descriptions.get(origin.upper(), f"未知来源: {origin}")


def _analyze_relocation_purpose(relocation_info: Dict[str, Any]) -> Dict[str, Any]:
    """分析重定位的用途和特性"""
    
    analysis = {
        "purpose": "未知用途",
        "characteristics": [],
        "likely_usage": "常规重定位"
    }
    
    # 基于重定位类型的分析
    if "type" in relocation_info:
        reloc_type = relocation_info["type"]["value"].upper()
        
        if "POINTER" in reloc_type:
            analysis["purpose"] = "指针地址修正"
            analysis["likely_usage"] = "修正数据指针或函数指针地址"
            analysis["characteristics"].append("需要地址重定位")
        
        elif "BRANCH" in reloc_type:
            analysis["purpose"] = "分支指令修正"
            analysis["likely_usage"] = "修正函数调用或跳转指令的目标地址"
            analysis["characteristics"].append("代码重定位")
        
        elif "GOT" in reloc_type:
            analysis["purpose"] = "全局偏移表访问"
            analysis["likely_usage"] = "通过GOT访问全局变量或函数"
            analysis["characteristics"].append("间接访问")
        
        elif "PLT" in reloc_type:
            analysis["purpose"] = "过程链接表调用"
            analysis["likely_usage"] = "延迟绑定的函数调用"
            analysis["characteristics"].append("延迟绑定")
        
        elif "DYLDINFO" in reloc_type:
            analysis["purpose"] = "动态链接器信息"
            analysis["likely_usage"] = "运行时动态链接和绑定"
            analysis["characteristics"].append("运行时处理")
    
    # 基于符号信息的分析
    if "symbol" in relocation_info and "error" not in relocation_info["symbol"]:
        symbol_name = relocation_info["symbol"]["name"]
        
        if symbol_name.startswith('_'):
            analysis["characteristics"].append("C符号重定位")
        elif symbol_name.startswith('$s') or symbol_name.startswith('_$s'):
            analysis["characteristics"].append("Swift符号重定位")
        elif symbol_name.startswith('__Z') or symbol_name.startswith('_Z'):
            analysis["characteristics"].append("C++符号重定位")
        
        # 常见系统函数
        if any(func in symbol_name.lower() for func in ['malloc', 'free', 'printf', 'objc_']):
            analysis["characteristics"].append("系统库函数重定位")
    
    # 基于来源的分析
    if "origin" in relocation_info:
        origin = relocation_info["origin"]["value"].upper()
        
        if "REBASE" in origin:
            analysis["characteristics"].append("基址重定位")
        elif "BIND" in origin:
            analysis["characteristics"].append("符号绑定")
        elif "LAZY" in origin:
            analysis["characteristics"].append("延迟处理")
    
    return analysis


def _calculate_relocation_statistics(relocations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算重定位统计信息"""
    
    stats = {
        "total_relocations": len(relocations),
        "relocations_by_type": {},
        "relocations_by_origin": {},
        "relocations_by_architecture": {},
        "relocations_with_symbols": 0,
        "relocations_with_segments": 0,
        "relocations_with_sections": 0,
        "address_range": {
            "min_address": None,
            "max_address": None,
            "span": 0
        },
        "symbol_relocations": 0,
        "pointer_relocations": 0,
        "branch_relocations": 0,
        "dyld_relocations": 0
    }
    
    addresses = []
    
    for relocation in relocations:
        if "error" in relocation:
            continue
        
        # 收集地址信息
        if "address" in relocation:
            addr = relocation["address"]["value"]
            addresses.append(addr)
        
        # 按类型统计
        if "type" in relocation:
            reloc_type = relocation["type"]["value"]
            stats["relocations_by_type"][reloc_type] = stats["relocations_by_type"].get(reloc_type, 0) + 1
            
            # 特定类型统计
            if "POINTER" in reloc_type.upper():
                stats["pointer_relocations"] += 1
            elif "BRANCH" in reloc_type.upper():
                stats["branch_relocations"] += 1
            elif "DYLD" in reloc_type.upper():
                stats["dyld_relocations"] += 1
        
        # 按来源统计
        if "origin" in relocation:
            origin = relocation["origin"]["value"]
            stats["relocations_by_origin"][origin] = stats["relocations_by_origin"].get(origin, 0) + 1
        
        # 按架构统计
        if "architecture" in relocation:
            arch = relocation["architecture"]["value"]
            stats["relocations_by_architecture"][arch] = stats["relocations_by_architecture"].get(arch, 0) + 1
        
        # 关联信息统计
        if "symbol" in relocation and "error" not in relocation["symbol"]:
            stats["relocations_with_symbols"] += 1
            stats["symbol_relocations"] += 1
        
        if "segment" in relocation and "error" not in relocation["segment"]:
            stats["relocations_with_segments"] += 1
        
        if "section" in relocation and "error" not in relocation["section"]:
            stats["relocations_with_sections"] += 1
    
    # 计算地址范围
    if addresses:
        stats["address_range"]["min_address"] = {
            "value": min(addresses),
            "hex": hex(min(addresses))
        }
        stats["address_range"]["max_address"] = {
            "value": max(addresses),
            "hex": hex(max(addresses))
        }
        stats["address_range"]["span"] = max(addresses) - min(addresses)
    
    return stats


def _extract_dyld_relocation_info(binary: lief.MachO.Binary) -> Dict[str, Any]:
    """提取 DYLD 相关的重定位信息"""
    
    dyld_info = {
        "has_dyld_info": False,
        "rebase_info": {},
        "bind_info": {},
        "weak_bind_info": {},
        "lazy_bind_info": {},
        "export_info": {}
    }
    
    try:
        # 检查是否有 DYLD 信息
        if hasattr(binary, 'dyld_info') and binary.dyld_info:
            dyld_info["has_dyld_info"] = True
            dyld_cmd = binary.dyld_info
            
            # Rebase 信息
            if hasattr(dyld_cmd, 'rebase_opcodes') and dyld_cmd.rebase_opcodes:
                dyld_info["rebase_info"] = {
                    "has_rebase_opcodes": True,
                    "opcodes_size": len(dyld_cmd.rebase_opcodes)
                }
            
            # Bind 信息
            if hasattr(dyld_cmd, 'bind_opcodes') and dyld_cmd.bind_opcodes:
                dyld_info["bind_info"] = {
                    "has_bind_opcodes": True,
                    "opcodes_size": len(dyld_cmd.bind_opcodes)
                }
            
            # Weak Bind 信息
            if hasattr(dyld_cmd, 'weak_bind_opcodes') and dyld_cmd.weak_bind_opcodes:
                dyld_info["weak_bind_info"] = {
                    "has_weak_bind_opcodes": True,
                    "opcodes_size": len(dyld_cmd.weak_bind_opcodes)
                }
            
            # Lazy Bind 信息
            if hasattr(dyld_cmd, 'lazy_bind_opcodes') and dyld_cmd.lazy_bind_opcodes:
                dyld_info["lazy_bind_info"] = {
                    "has_lazy_bind_opcodes": True,
                    "opcodes_size": len(dyld_cmd.lazy_bind_opcodes)
                }
            
            # Export 信息
            if hasattr(dyld_cmd, 'export_trie') and dyld_cmd.export_trie:
                dyld_info["export_info"] = {
                    "has_export_trie": True,
                    "trie_size": len(dyld_cmd.export_trie)
                }
    
    except Exception as e:
        dyld_info["error"] = f"获取 DYLD 信息时发生错误: {str(e)}"
    
    return dyld_info
