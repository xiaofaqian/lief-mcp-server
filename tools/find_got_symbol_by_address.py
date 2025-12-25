"""
通过地址查找 Mach-O 文件中 GOT 符号的工具

此工具专门用于根据给定的内存地址查找对应的 GOT (Global Offset Table) 符号信息。
支持精确地址匹配和范围搜索，提供详细的符号绑定和重定位信息。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
from .common import parse_macho, parse_number, select_architecture_by_index, validate_file_path


def find_got_symbol_by_address(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    target_address: Annotated[str, Field(
        description="要查找的目标地址，支持十六进制格式（如0x100001000）或十进制格式（如4295000072）"
    )],
    architecture_index: Annotated[int, Field(
        description="对于Fat Binary文件，指定要分析的架构索引（从0开始）。如果不指定，将分析第一个架构",
        ge=0
    )] = 0,
    search_range: Annotated[int, Field(
        description="搜索范围（字节），0表示精确匹配，大于0表示在目标地址前后指定范围内搜索相关符号",
        ge=0
    )] = 0
) -> Dict[str, Any]:
    """
    通过地址查找 Mach-O 文件中的 GOT 符号信息。
    
    该工具提供以下功能：
    - 根据内存地址精确查找对应的 GOT 符号
    - 支持地址范围搜索，查找附近的相关符号
    - 提供详细的绑定信息和重定位数据
    - 显示符号所属的库和段信息
    - 分析 GOT 表项的类型和用途
    
    支持单架构和 Fat Binary 文件的符号查找。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error
        
        target_addr, _, parse_error = parse_number(target_address, "auto")
        if parse_error:
            return {
                "error": f"无效的地址格式: {target_address}",
                "suggestion": "请使用十六进制格式（如0x100001000）或十进制格式（如4295000072）"
            }
        
        fat_binary, parse_error = parse_macho(file_path)
        if parse_error:
            return parse_error
        
        binary, arch_error = select_architecture_by_index(fat_binary, architecture_index)
        if arch_error:
            return arch_error
        
        # 查找符号
        result = _find_symbol_by_address(binary, target_addr, search_range, architecture_index)
        result["file_path"] = file_path
        result["target_address"] = {
            "input": target_address,
            "parsed": target_addr,
            "hex": hex(target_addr)
        }
        result["search_range"] = search_range
        
        return result
        
    except Exception as e:
        return {
            "error": f"查找符号时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "target_address": target_address,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _find_symbol_by_address(binary: lief.MachO.Binary, target_addr: int, search_range: int, arch_index: int) -> Dict[str, Any]:
    """在指定架构中查找目标地址对应的符号"""
    
    header = binary.header
    
    result = {
        "architecture_index": arch_index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "exact_matches": [],
        "range_matches": [],
        "analysis": {}
    }
    
    # 收集绑定信息
    bindings_by_address = {}
    try:
        if hasattr(binary, 'bindings'):
            for binding in binary.bindings:
                try:
                    address = getattr(binding, 'address', 0)
                    symbol_name = ""
                    if hasattr(binding, 'symbol') and binding.symbol:
                        symbol_name = getattr(binding.symbol, 'name', '')
                    
                    library = ""
                    if hasattr(binding, 'library') and binding.library:
                        library = getattr(binding.library, 'name', '')
                    
                    segment = ""
                    if hasattr(binding, 'segment') and binding.segment:
                        segment = getattr(binding.segment, 'name', '')
                    
                    binding_type = ""
                    if hasattr(binding, 'binding_type'):
                        binding_type = str(binding.binding_type)
                    
                    bindings_by_address[address] = {
                        'symbol': symbol_name,
                        'library': library,
                        'segment': segment,
                        'binding_type': binding_type,
                        'binding_obj': binding
                    }
                except Exception:
                    continue
    except Exception as e:
        result["analysis"]["binding_error"] = f"获取绑定信息时出错: {str(e)}"
    
    # 收集重定位信息
    relocations_by_address = {}
    try:
        if hasattr(binary, 'relocations'):
            for relocation in binary.relocations:
                try:
                    address = getattr(relocation, 'address', 0)
                    
                    reloc_info = {
                        'type': str(getattr(relocation, 'type', 'UNKNOWN')),
                        'size': str(getattr(relocation, 'size', '0')),
                        'origin': str(getattr(relocation, 'origin', 'UNKNOWN')),
                        'symbol': '',
                        'section': ''
                    }
                    
                    # 获取符号信息
                    if hasattr(relocation, 'symbol') and relocation.symbol:
                        reloc_info['symbol'] = getattr(relocation.symbol, 'name', '')
                    
                    # 获取段.节信息
                    if hasattr(relocation, 'section') and relocation.section:
                        try:
                            section = relocation.section
                            if hasattr(section, 'name') and hasattr(section, 'segment'):
                                segment_name = getattr(section.segment, 'name', '') if section.segment else ''
                                section_name = getattr(section, 'name', '')
                                if segment_name and section_name:
                                    reloc_info['section'] = f"{segment_name}.{section_name}"
                        except:
                            pass
                    
                    relocations_by_address[address] = reloc_info
                    
                except Exception:
                    continue
    except Exception as e:
        result["analysis"]["relocation_error"] = f"获取重定位信息时出错: {str(e)}"
    
    # 精确匹配查找
    exact_match = None
    
    # 优先查找绑定信息
    if target_addr in bindings_by_address:
        binding_info = bindings_by_address[target_addr]
        exact_match = {
            "address": target_addr,
            "address_hex": hex(target_addr),
            "symbol_name": binding_info['symbol'],
            "library": _extract_library_name(binding_info['library']),
            "segment": binding_info['segment'],
            "binding_type": binding_info['binding_type'],
            "source": "BINDING",
            "details": _analyze_binding_details(binding_info['binding_obj'])
        }
    
    # 查找重定位信息
    elif target_addr in relocations_by_address:
        reloc_info = relocations_by_address[target_addr]
        exact_match = {
            "address": target_addr,
            "address_hex": hex(target_addr),
            "symbol_name": reloc_info['symbol'],
            "library": "unknown",
            "segment": reloc_info['section'],
            "relocation_type": reloc_info['type'],
            "relocation_size": reloc_info['size'],
            "relocation_origin": reloc_info['origin'],
            "source": "RELOCATION",
            "details": {}
        }
    
    if exact_match:
        result["exact_matches"].append(exact_match)
    
    # 范围搜索
    if search_range > 0:
        range_matches = []
        min_addr = target_addr - search_range
        max_addr = target_addr + search_range
        
        # 在绑定信息中搜索
        for addr, binding_info in bindings_by_address.items():
            if min_addr <= addr <= max_addr and addr != target_addr:
                range_match = {
                    "address": addr,
                    "address_hex": hex(addr),
                    "offset_from_target": addr - target_addr,
                    "symbol_name": binding_info['symbol'],
                    "library": _extract_library_name(binding_info['library']),
                    "segment": binding_info['segment'],
                    "binding_type": binding_info['binding_type'],
                    "source": "BINDING"
                }
                range_matches.append(range_match)
        
        # 在重定位信息中搜索
        for addr, reloc_info in relocations_by_address.items():
            if min_addr <= addr <= max_addr and addr != target_addr:
                # 检查是否已经在绑定信息中找到
                if not any(match["address"] == addr for match in range_matches):
                    range_match = {
                        "address": addr,
                        "address_hex": hex(addr),
                        "offset_from_target": addr - target_addr,
                        "symbol_name": reloc_info['symbol'],
                        "library": "unknown",
                        "segment": reloc_info['section'],
                        "relocation_type": reloc_info['type'],
                        "source": "RELOCATION"
                    }
                    range_matches.append(range_match)
        
        # 按地址排序
        range_matches.sort(key=lambda x: x["address"])
        result["range_matches"] = range_matches
    
    # 添加分析信息
    result["analysis"] = {
        "total_bindings": len(bindings_by_address),
        "total_relocations": len(relocations_by_address),
        "exact_match_found": len(result["exact_matches"]) > 0,
        "range_matches_found": len(result["range_matches"]) if search_range > 0 else None,
        "got_analysis": _analyze_got_context(target_addr, bindings_by_address, relocations_by_address)
    }
    
    return result


def _analyze_binding_details(binding) -> Dict[str, Any]:
    """分析绑定对象的详细信息"""
    
    details = {}
    
    try:
        # 基本绑定信息
        if hasattr(binding, 'address'):
            details["address"] = hex(binding.address)
        
        if hasattr(binding, 'addend'):
            details["addend"] = binding.addend
        
        if hasattr(binding, 'library_ordinal'):
            details["library_ordinal"] = binding.library_ordinal
        
        if hasattr(binding, 'weak_import'):
            details["weak_import"] = binding.weak_import
        
        # 绑定类型分析
        if hasattr(binding, 'binding_type'):
            binding_type = str(binding.binding_type)
            details["binding_type_analysis"] = _get_binding_type_description(binding_type)
        
        # 段信息
        if hasattr(binding, 'segment') and binding.segment:
            segment = binding.segment
            details["segment_info"] = {
                "name": getattr(segment, 'name', ''),
                "virtual_address": hex(getattr(segment, 'virtual_address', 0)),
                "virtual_size": getattr(segment, 'virtual_size', 0)
            }
    
    except Exception as e:
        details["analysis_error"] = f"分析绑定详情时出错: {str(e)}"
    
    return details


def _get_binding_type_description(binding_type: str) -> str:
    """获取绑定类型的描述"""
    
    type_descriptions = {
        "POINTER": "指针绑定，直接指向符号地址",
        "TEXT_ABSOLUTE32": "32位绝对文本绑定",
        "TEXT_PCREL32": "32位PC相对文本绑定",
        "THREADED": "线程化绑定，用于链式修复"
    }
    
    return type_descriptions.get(binding_type, f"未知绑定类型: {binding_type}")


def _analyze_got_context(target_addr: int, bindings: Dict[int, Any], relocations: Dict[int, Any]) -> Dict[str, Any]:
    """分析目标地址在 GOT 上下文中的位置和意义"""
    
    analysis = {
        "is_likely_got": False,
        "got_section_detected": False,
        "nearby_got_entries": 0,
        "address_pattern": "unknown"
    }
    
    # 检查是否在已知的 GOT 相关段中
    got_sections = ["__DATA.__got", "__DATA_CONST.__got", "__DATA.__la_symbol_ptr", "__DATA.__nl_symbol_ptr"]
    
    for addr, binding_info in bindings.items():
        segment = binding_info.get('segment', '')
        if any(got_sec in segment for got_sec in got_sections):
            analysis["got_section_detected"] = True
            if abs(addr - target_addr) <= 64:  # 64字节范围内
                analysis["nearby_got_entries"] += 1
    
    for addr, reloc_info in relocations.items():
        section = reloc_info.get('section', '')
        if any(got_sec in section for got_sec in got_sections):
            analysis["got_section_detected"] = True
            if abs(addr - target_addr) <= 64:
                analysis["nearby_got_entries"] += 1
    
    # 判断是否可能是 GOT 表项
    if analysis["got_section_detected"] or analysis["nearby_got_entries"] > 0:
        analysis["is_likely_got"] = True
    
    # 分析地址模式
    if target_addr % 8 == 0:
        analysis["address_pattern"] = "8字节对齐（64位指针）"
    elif target_addr % 4 == 0:
        analysis["address_pattern"] = "4字节对齐（32位指针）"
    else:
        analysis["address_pattern"] = "非标准对齐"
    
    return analysis


def _extract_library_name(library_path: str) -> str:
    """从库路径中提取简洁的库名"""
    
    if not library_path:
        return "unknown"
    
    # 处理框架路径
    if '.framework/' in library_path:
        parts = library_path.split('.framework/')
        if len(parts) >= 2:
            framework_name = parts[0].split('/')[-1]
            return framework_name
    
    # 处理普通库路径
    library_name = library_path.split('/')[-1]
    
    return library_name
