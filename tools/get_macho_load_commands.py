"""
Mach-O 加载命令信息获取工具

此工具专门用于获取 Mach-O 文件中的所有加载命令（Load Commands）信息，包括命令类型、大小、具体内容等详细数据。
提供完整的加载命令结构解析，帮助理解二进制文件的加载过程和依赖关系。
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief
import os


def get_macho_load_commands(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )]
) -> Dict[str, Any]:
    """
    获取 Mach-O 文件中的所有加载命令信息，包括命令类型、大小、具体内容等详细数据。
    
    该工具解析 Mach-O 文件的加载命令结构，提供：
    - 加载命令类型和标识符
    - 命令大小和偏移信息
    - 特定命令的详细内容解析
    - 依赖库和链接信息
    - 段和节的加载配置
    - 动态链接器相关命令
    - 代码签名和加密信息
    
    支持单架构和 Fat Binary 文件的加载命令信息提取。
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
        
        # 遍历所有架构的加载命令信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_commands = _extract_load_commands_info(binary, i)
                result["architectures"].append(arch_commands)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 加载命令时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件加载命令时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_load_commands_info(binary: lief.MachO.Binary, index: int) -> Dict[str, Any]:
    """提取单个架构的加载命令详细信息"""
    
    header = binary.header
    commands = binary.commands
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "load_commands_count": len(commands),
        "load_commands_size": header.sizeof_cmds,
        "load_commands": []
    }
    
    # 遍历所有加载命令
    for i, command in enumerate(commands):
        try:
            command_info = _extract_single_command_info(command, i)
            arch_info["load_commands"].append(command_info)
        except Exception as e:
            arch_info["load_commands"].append({
                "index": i,
                "command_type": str(type(command).__name__) if hasattr(command, '__class__') else 'unknown',
                "error": f"解析加载命令时发生错误: {str(e)}"
            })
    
    # 添加加载命令统计信息
    arch_info["command_statistics"] = _calculate_command_statistics(arch_info["load_commands"])
    
    return arch_info


def _extract_single_command_info(command, index: int) -> Dict[str, Any]:
    """提取单个加载命令的详细信息"""
    
    # 基本命令信息
    command_info = {
        "index": index,
        "command_type": str(type(command).__name__),
        "command_id": str(command.command) if hasattr(command, 'command') else 'unknown',
        "size": command.size if hasattr(command, 'size') else 0
    }
    
    # 根据命令类型提取特定信息
    try:
        if hasattr(command, 'command'):
            command_type_str = str(command.command)
            command_info["command_name"] = command_type_str
            command_info["description"] = _get_command_description(command_type_str)
            
            # 根据具体命令类型提取详细信息
            specific_info = _extract_command_specific_info(command, command_type_str)
            if specific_info:
                command_info["details"] = specific_info
        
    except Exception as e:
        command_info["parsing_error"] = f"解析命令详情时发生错误: {str(e)}"
    
    return command_info


def _extract_command_specific_info(command, command_type: str) -> Dict[str, Any]:
    """根据命令类型提取特定信息"""
    
    details = {}
    
    try:
        # LC_SEGMENT / LC_SEGMENT_64 - 段加载命令
        if "SEGMENT" in command_type and hasattr(command, 'name'):
            details.update({
                "segment_name": command.name,
                "virtual_address": {
                    "value": command.virtual_address,
                    "hex": hex(command.virtual_address)
                } if hasattr(command, 'virtual_address') else None,
                "virtual_size": {
                    "value": command.virtual_size,
                    "hex": hex(command.virtual_size),
                    "human_readable": _format_size(command.virtual_size)
                } if hasattr(command, 'virtual_size') else None,
                "file_offset": {
                    "value": command.file_offset,
                    "hex": hex(command.file_offset)
                } if hasattr(command, 'file_offset') else None,
                "file_size": {
                    "value": command.file_size,
                    "hex": hex(command.file_size),
                    "human_readable": _format_size(command.file_size)
                } if hasattr(command, 'file_size') else None,
                "max_protection": _parse_protection_flags(command.max_protection) if hasattr(command, 'max_protection') else None,
                "init_protection": _parse_protection_flags(command.init_protection) if hasattr(command, 'init_protection') else None,
                "sections_count": len(command.sections) if hasattr(command, 'sections') else 0
            })
        
        # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB - 动态库加载命令
        elif "DYLIB" in command_type and hasattr(command, 'name'):
            details.update({
                "library_name": command.name,
                "timestamp": command.timestamp if hasattr(command, 'timestamp') else None,
                "current_version": {
                    "raw": command.current_version,
                    "formatted": _format_version(command.current_version)
                } if hasattr(command, 'current_version') else None,
                "compatibility_version": {
                    "raw": command.compatibility_version,
                    "formatted": _format_version(command.compatibility_version)
                } if hasattr(command, 'compatibility_version') else None
            })
        
        # LC_DYLD_INFO / LC_DYLD_INFO_ONLY - 动态链接器信息
        elif "DYLD_INFO" in command_type:
            details.update({
                "rebase_info": {
                    "offset": command.rebase_opcodes_offset if hasattr(command, 'rebase_opcodes_offset') else None,
                    "size": command.rebase_opcodes_size if hasattr(command, 'rebase_opcodes_size') else None
                },
                "bind_info": {
                    "offset": command.bind_opcodes_offset if hasattr(command, 'bind_opcodes_offset') else None,
                    "size": command.bind_opcodes_size if hasattr(command, 'bind_opcodes_size') else None
                },
                "weak_bind_info": {
                    "offset": command.weak_bind_opcodes_offset if hasattr(command, 'weak_bind_opcodes_offset') else None,
                    "size": command.weak_bind_opcodes_size if hasattr(command, 'weak_bind_opcodes_size') else None
                },
                "lazy_bind_info": {
                    "offset": command.lazy_bind_opcodes_offset if hasattr(command, 'lazy_bind_opcodes_offset') else None,
                    "size": command.lazy_bind_opcodes_size if hasattr(command, 'lazy_bind_opcodes_size') else None
                },
                "export_info": {
                    "offset": command.export_trie_offset if hasattr(command, 'export_trie_offset') else None,
                    "size": command.export_trie_size if hasattr(command, 'export_trie_size') else None
                }
            })
        
        # LC_SYMTAB - 符号表命令
        elif "SYMTAB" in command_type:
            details.update({
                "symbol_table": {
                    "offset": command.symbol_offset if hasattr(command, 'symbol_offset') else None,
                    "count": command.nb_symbols if hasattr(command, 'nb_symbols') else None
                },
                "string_table": {
                    "offset": command.string_offset if hasattr(command, 'string_offset') else None,
                    "size": command.string_size if hasattr(command, 'string_size') else None
                }
            })
        
        # LC_DYSYMTAB - 动态符号表命令
        elif "DYSYMTAB" in command_type:
            details.update({
                "local_symbols": {
                    "index": command.idx_local_symbol if hasattr(command, 'idx_local_symbol') else None,
                    "count": command.nb_local_symbols if hasattr(command, 'nb_local_symbols') else None
                },
                "external_symbols": {
                    "index": command.idx_external_define_symbol if hasattr(command, 'idx_external_define_symbol') else None,
                    "count": command.nb_external_define_symbols if hasattr(command, 'nb_external_define_symbols') else None
                },
                "undefined_symbols": {
                    "index": command.idx_undefined_symbol if hasattr(command, 'idx_undefined_symbol') else None,
                    "count": command.nb_undefined_symbols if hasattr(command, 'nb_undefined_symbols') else None
                }
            })
        
        # LC_MAIN - 主程序入口点
        elif "MAIN" in command_type:
            details.update({
                "entrypoint": {
                    "offset": command.entrypoint if hasattr(command, 'entrypoint') else None,
                    "hex": hex(command.entrypoint) if hasattr(command, 'entrypoint') else None
                },
                "stack_size": {
                    "value": command.stack_size if hasattr(command, 'stack_size') else None,
                    "human_readable": _format_size(command.stack_size) if hasattr(command, 'stack_size') else None
                }
            })
        
        # LC_UUID - UUID命令
        elif "UUID" in command_type and hasattr(command, 'uuid'):
            details.update({
                "uuid": command.uuid.hex() if hasattr(command.uuid, 'hex') else str(command.uuid)
            })
        
        # LC_VERSION_MIN_* - 最小版本命令
        elif "VERSION_MIN" in command_type:
            details.update({
                "version": {
                    "raw": command.version if hasattr(command, 'version') else None,
                    "formatted": _format_version(command.version) if hasattr(command, 'version') else None
                },
                "sdk_version": {
                    "raw": command.sdk if hasattr(command, 'sdk') else None,
                    "formatted": _format_version(command.sdk) if hasattr(command, 'sdk') else None
                }
            })
        
        # LC_SOURCE_VERSION - 源代码版本
        elif "SOURCE_VERSION" in command_type and hasattr(command, 'version'):
            details.update({
                "source_version": command.version
            })
        
        # LC_RPATH - 运行时搜索路径
        elif "RPATH" in command_type and hasattr(command, 'path'):
            details.update({
                "path": command.path
            })
        
        # LC_CODE_SIGNATURE - 代码签名
        elif "CODE_SIGNATURE" in command_type:
            details.update({
                "data_offset": command.data_offset if hasattr(command, 'data_offset') else None,
                "data_size": {
                    "value": command.data_size if hasattr(command, 'data_size') else None,
                    "human_readable": _format_size(command.data_size) if hasattr(command, 'data_size') else None
                }
            })
        
        # LC_ENCRYPTION_INFO - 加密信息
        elif "ENCRYPTION_INFO" in command_type:
            details.update({
                "crypt_offset": command.crypt_offset if hasattr(command, 'crypt_offset') else None,
                "crypt_size": {
                    "value": command.crypt_size if hasattr(command, 'crypt_size') else None,
                    "human_readable": _format_size(command.crypt_size) if hasattr(command, 'crypt_size') else None
                },
                "crypt_id": command.crypt_id if hasattr(command, 'crypt_id') else None
            })
        
        # 通用属性提取
        for attr in ['name', 'path', 'offset', 'size', 'count', 'flags']:
            if hasattr(command, attr):
                try:
                    value = getattr(command, attr)
                    if value is not None:
                        details[attr] = value
                except:
                    pass
    
    except Exception as e:
        details["extraction_error"] = f"提取命令详情时发生错误: {str(e)}"
    
    return details


def _get_command_description(command_type: str) -> str:
    """获取加载命令类型的描述"""
    
    descriptions = {
        "LC_SEGMENT": "32位段加载命令",
        "LC_SEGMENT_64": "64位段加载命令",
        "LC_SYMTAB": "符号表命令",
        "LC_DYSYMTAB": "动态符号表命令",
        "LC_LOAD_DYLIB": "加载动态库命令",
        "LC_LOAD_WEAK_DYLIB": "加载弱引用动态库命令",
        "LC_ID_DYLIB": "动态库标识命令",
        "LC_DYLD_INFO": "动态链接器信息命令",
        "LC_DYLD_INFO_ONLY": "仅动态链接器信息命令",
        "LC_UUID": "UUID标识命令",
        "LC_VERSION_MIN_MACOSX": "macOS最小版本命令",
        "LC_VERSION_MIN_IPHONEOS": "iOS最小版本命令",
        "LC_VERSION_MIN_TVOS": "tvOS最小版本命令",
        "LC_VERSION_MIN_WATCHOS": "watchOS最小版本命令",
        "LC_SOURCE_VERSION": "源代码版本命令",
        "LC_MAIN": "主程序入口点命令",
        "LC_RPATH": "运行时搜索路径命令",
        "LC_CODE_SIGNATURE": "代码签名命令",
        "LC_SEGMENT_SPLIT_INFO": "段分割信息命令",
        "LC_FUNCTION_STARTS": "函数起始地址命令",
        "LC_DATA_IN_CODE": "代码中数据命令",
        "LC_DYLIB_CODE_SIGN_DRS": "动态库代码签名命令",
        "LC_ENCRYPTION_INFO": "加密信息命令",
        "LC_ENCRYPTION_INFO_64": "64位加密信息命令",
        "LC_LINKER_OPTION": "链接器选项命令",
        "LC_LINKER_OPTIMIZATION_HINT": "链接器优化提示命令",
        "LC_BUILD_VERSION": "构建版本命令"
    }
    
    # 查找完全匹配
    if command_type in descriptions:
        return descriptions[command_type]
    
    # 查找部分匹配
    for key, desc in descriptions.items():
        if key in command_type:
            return desc
    
    return f"加载命令类型: {command_type}"


def _parse_protection_flags(protection: int) -> Dict[str, Any]:
    """解析保护标志位"""
    
    flags = []
    
    if protection & 0x1:  # VM_PROT_READ
        flags.append("READ")
    if protection & 0x2:  # VM_PROT_WRITE
        flags.append("WRITE")
    if protection & 0x4:  # VM_PROT_EXECUTE
        flags.append("EXECUTE")
    
    return {
        "value": protection,
        "hex": hex(protection),
        "flags": flags if flags else ["NONE"],
        "description": " | ".join(flags) if flags else "无权限"
    }


def _format_version(version: int) -> str:
    """格式化版本号"""
    
    if version == 0:
        return "0.0.0"
    
    try:
        major = (version >> 16) & 0xFFFF
        minor = (version >> 8) & 0xFF
        patch = version & 0xFF
        return f"{major}.{minor}.{patch}"
    except:
        return str(version)


def _calculate_command_statistics(commands: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算加载命令统计信息"""
    
    stats = {
        "total_commands": len(commands),
        "total_size": 0,
        "command_types": {},
        "largest_command": None,
        "smallest_command": None,
        "commands_with_errors": 0
    }
    
    largest_size = 0
    smallest_size = float('inf')
    
    for command in commands:
        if "error" in command:
            stats["commands_with_errors"] += 1
            continue
        
        # 累计大小
        if "size" in command:
            size = command["size"]
            stats["total_size"] += size
            
            # 找最大最小命令
            if size > largest_size:
                largest_size = size
                stats["largest_command"] = {
                    "index": command.get("index", -1),
                    "type": command.get("command_name", "unknown"),
                    "size": size
                }
            
            if size < smallest_size and size > 0:
                smallest_size = size
                stats["smallest_command"] = {
                    "index": command.get("index", -1),
                    "type": command.get("command_name", "unknown"),
                    "size": size
                }
        
        # 统计命令类型
        if "command_name" in command:
            cmd_type = command["command_name"]
            stats["command_types"][cmd_type] = stats["command_types"].get(cmd_type, 0) + 1
    
    # 格式化总大小
    stats["total_size_formatted"] = _format_size(stats["total_size"])
    
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
