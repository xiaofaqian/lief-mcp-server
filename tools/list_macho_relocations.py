import lief
import re
from typing import Annotated, Optional
from pydantic import Field


def list_macho_relocations(
    file_path: Annotated[str, Field(description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld")],
    offset: Annotated[int, Field(description="起始位置偏移量，从第几个重定位项开始返回（从0开始计数）", ge=0)] = 0,
    count: Annotated[int, Field(description="返回的重定位项数量，最大100条，0表示返回所有剩余重定位项", ge=0, le=100)] = 20,
    symbol_filter: Annotated[Optional[str], Field(description="符号名称过滤器，支持正则表达式匹配。例如：'_err' 或 '^_.*' 或 '.*malloc.*'")] = None,
    architecture_index: Annotated[int, Field(description="对于Fat Binary文件，指定要分析的架构索引（从0开始）。如果不指定，将分析第一个架构", ge=0)] = 0,
    include_symbol_table_info: Annotated[bool, Field(description="是否包含符号表和动态链接器信息的详细统计")] = True
) -> str:
    """
    列出 Mach-O 文件中的重定位信息，包括地址、类型、符号名称等详细数据。

    该工具解析 Mach-O 文件的重定位结构，提供：
    - 重定位地址和类型信息
    - 符号名称和所属段信息
    - 重定位来源（DYLDINFO、符号表等）
    - 支持符号名称过滤和分页显示
    - 符号表和动态链接器统计信息

    支持单架构和 Fat Binary 文件的重定位信息提取。
    """
    
    try:
        # 解析 Mach-O 文件
        fat_binary = lief.MachO.parse(file_path)
        if not fat_binary:
            return f"错误：无法解析文件 {file_path}"
        
        # 选择架构
        if len(fat_binary) <= architecture_index:
            return f"错误：架构索引 {architecture_index} 超出范围，文件只有 {len(fat_binary)} 个架构"
        
        binary = fat_binary.at(architecture_index)
        if not binary:
            return f"错误：无法获取架构 {architecture_index} 的二进制文件"
        
        result = []
        
        # 添加文件基本信息
        result.append(f"文件: {file_path}")
        result.append(f"架构: {str(binary.header.cpu_type)} ({architecture_index})")
        result.append("")
        
        # 获取符号表根节点地址信息
        symbol_table_info = []
        if include_symbol_table_info:
            try:
                # 获取符号表相关信息
                if hasattr(binary, 'symbols') and binary.symbols:
                    symbol_table_info.append(f"符号表统计:")
                    symbol_table_info.append(f"  总符号数量: {len(binary.symbols)}")
                
                # 获取 LC_SYMTAB 加载命令信息
                for cmd in binary.commands:
                    if hasattr(cmd, 'command') and str(cmd.command) == "SYMTAB":
                        if hasattr(cmd, 'symbol_offset'):
                            symbol_table_info.append(f"  符号表文件偏移: 0x{cmd.symbol_offset:x}")
                        if hasattr(cmd, 'numberof_symbols'):
                            symbol_table_info.append(f"  符号表项数量: {cmd.numberof_symbols}")
                        if hasattr(cmd, 'strings_offset'):
                            symbol_table_info.append(f"  字符串表偏移: 0x{cmd.strings_offset:x}")
                        if hasattr(cmd, 'strings_size'):
                            symbol_table_info.append(f"  字符串表大小: {cmd.strings_size} 字节")
                        break
                
                # 获取 dyld_info 相关信息
                if hasattr(binary, 'dyld_info') and binary.dyld_info:
                    dyld_info = binary.dyld_info
                    symbol_table_info.append(f"  动态链接信息:")
                    if hasattr(dyld_info, 'bind_off') and dyld_info.bind_off > 0:
                        symbol_table_info.append(f"    绑定信息偏移: 0x{dyld_info.bind_off:x}")
                    if hasattr(dyld_info, 'export_off') and dyld_info.export_off > 0:
                        symbol_table_info.append(f"    导出信息偏移: 0x{dyld_info.export_off:x}")
                    if hasattr(dyld_info, 'rebase_off') and dyld_info.rebase_off > 0:
                        symbol_table_info.append(f"    重定位信息偏移: 0x{dyld_info.rebase_off:x}")
                
            except Exception as e:
                symbol_table_info.append(f"获取符号表信息时出错: {str(e)}")
        
        if symbol_table_info:
            result.extend(symbol_table_info)
            result.append("")
        
        # 获取重定位信息和绑定信息
        relocations = []
        
        # 首先收集绑定信息（这些包含符号名称）
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
                        
                        bindings_by_address[address] = {
                            'symbol': symbol_name,
                            'library': library,
                            'segment': segment,
                            'binding_str': str(binding)
                        }
                    except Exception as e:
                        continue
        except Exception as e:
            result.append(f"获取绑定信息时出错: {str(e)}")
        
        # 然后处理重定位信息
        try:
            if hasattr(binary, 'relocations'):
                for relocation in binary.relocations:
                    try:
                        # 获取重定位地址
                        address = getattr(relocation, 'address', 0)
                        
                        # 获取重定位类型和大小
                        reloc_type = "UNKNOWN"
                        size = "0"
                        origin = "UNKNOWN"
                        section_info = ""
                        symbol_name = ""
                        
                        # 尝试获取重定位的详细属性
                        if hasattr(relocation, 'type'):
                            try:
                                reloc_type = str(relocation.type)
                            except:
                                reloc_type = "FIXUP"
                        
                        if hasattr(relocation, 'size'):
                            try:
                                size = str(relocation.size)
                            except:
                                size = "64"
                        
                        if hasattr(relocation, 'origin'):
                            try:
                                origin = str(relocation.origin)
                            except:
                                origin = "CHAINED_FIXUPS"
                        
                        # 尝试获取段和节信息
                        if hasattr(relocation, 'section') and relocation.section:
                            try:
                                section = relocation.section
                                if hasattr(section, 'name') and hasattr(section, 'segment'):
                                    segment_name = getattr(section.segment, 'name', '') if section.segment else ''
                                    section_name = getattr(section, 'name', '')
                                    if segment_name and section_name:
                                        section_info = f"{segment_name}.{section_name}"
                                    elif section_name:
                                        section_info = section_name
                            except:
                                pass
                        
                        # 尝试获取符号信息
                        if hasattr(relocation, 'symbol') and relocation.symbol:
                            try:
                                symbol_name = getattr(relocation.symbol, 'name', '')
                            except:
                                pass
                        
                        # 如果没有符号信息，检查绑定信息
                        if not symbol_name and address in bindings_by_address:
                            binding_info = bindings_by_address[address]
                            symbol_name = binding_info['symbol']
                            if binding_info['library']:
                                symbol_name += f" ({binding_info['library']})"
                        
                        # 如果仍然没有段.节信息，尝试从字符串表示中提取
                        if not section_info:
                            reloc_str = str(relocation).strip()
                            if "__DATA_CONST.__got" in reloc_str:
                                section_info = "__DATA_CONST.__got"
                            elif "__DATA.__got" in reloc_str:
                                section_info = "__DATA.__got"
                            elif "__DATA.__la_symbol_ptr" in reloc_str:
                                section_info = "__DATA.__la_symbol_ptr"
                            elif "__TEXT.__text" in reloc_str:
                                section_info = "__TEXT.__text"
                        
                        reloc_info = {
                            'address': address,
                            'type': reloc_type,
                            'size': size,
                            'origin': origin,
                            'section': section_info,
                            'symbol': symbol_name,
                            'raw_string': str(relocation)
                        }
                        
                        relocations.append(reloc_info)
                        
                    except Exception as e:
                        # 单个重定位项解析失败，继续处理其他项
                        relocations.append({
                            'address': 0,
                            'type': 'ERROR',
                            'size': '',
                            'origin': '',
                            'section': '',
                            'symbol': f'解析错误: {str(e)}',
                            'raw_string': f"ERROR: {str(e)}"
                        })
                        continue
            
            # 如果重定位项没有符号信息，或者用户想要查看绑定信息，添加绑定信息
            if bindings_by_address:
                # 检查是否有符号过滤器，如果有，先检查绑定信息中是否有匹配项
                has_symbol_filter = symbol_filter is not None
                
                # 添加绑定信息作为额外的重定位项
                for address, binding_info in bindings_by_address.items():
                    # 如果有符号过滤器，先检查是否匹配
                    if has_symbol_filter:
                        try:
                            pattern = re.compile(symbol_filter, re.IGNORECASE)
                            if not (pattern.search(binding_info['symbol']) or pattern.search(binding_info['binding_str'])):
                                continue
                        except re.error:
                            continue
                    
                    reloc_info = {
                        'address': address,
                        'type': 'BINDING',
                        'size': '64',
                        'origin': 'DYLD_INFO',
                        'section': binding_info['segment'],
                        'symbol': binding_info['symbol'],
                        'raw_string': binding_info['binding_str']
                    }
                    relocations.append(reloc_info)
            
        except Exception as e:
            result.append(f"获取重定位信息时出错: {str(e)}")
            return "\n".join(result)
        
        # 应用符号过滤器
        if symbol_filter:
            try:
                pattern = re.compile(symbol_filter, re.IGNORECASE)
                filtered_relocations = []
                for reloc in relocations:
                    if pattern.search(reloc['symbol']) or pattern.search(reloc['raw_string']):
                        filtered_relocations.append(reloc)
                relocations = filtered_relocations
            except re.error as e:
                result.append(f"正则表达式错误: {str(e)}")
                return "\n".join(result)
        
        # 应用分页
        total_relocations = len(relocations)
        if offset >= total_relocations:
            result.append(f"偏移量 {offset} 超出范围，总共有 {total_relocations} 个重定位项")
            return "\n".join(result)
        
        end_index = offset + count if count > 0 else total_relocations
        end_index = min(end_index, total_relocations)
        page_relocations = relocations[offset:end_index]
        
        # 添加统计信息
        result.append(f"重定位信息统计:")
        result.append(f"  总重定位项数量: {total_relocations}")
        if symbol_filter:
            result.append(f"  过滤条件: {symbol_filter}")
        result.append(f"  显示范围: {offset} - {end_index-1}")
        result.append("")
        
        # 添加表头
        result.append("地址      类型     大小 来源      段.节                    符号名称")
        result.append("-" * 80)
        
        # 添加重定位信息
        if not page_relocations:
            result.append("未找到匹配的重定位项")
        else:
            for reloc in page_relocations:
                try:
                    # 格式化输出
                    address_str = f"{reloc['address']:08x}"
                    type_str = reloc['type'][:8].ljust(8)
                    size_str = reloc['size'][:4].ljust(4)
                    origin_str = reloc['origin'][:8].ljust(8)
                    section_str = reloc['section'][:20].ljust(20)
                    symbol_str = reloc['symbol']
                    
                    line = f"{address_str} {type_str} {size_str} {origin_str} {section_str} {symbol_str}"
                    result.append(line)
                    
                except Exception as e:
                    result.append(f"格式化重定位项时出错: {str(e)}")
        
        # 添加分页提示
        if end_index < total_relocations:
            result.append("")
            result.append(f"还有 {total_relocations - end_index} 个重定位项未显示")
            result.append(f"使用 offset={end_index} 查看更多")
        
        return "\n".join(result)
        
    except Exception as e:
        return f"解析文件时发生错误: {str(e)}"
