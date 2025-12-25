"""
Mach-O 符号替换工具

此工具专门用于替换 Mach-O 文件中的符号绑定，将原始符号重定向到自定义 dylib 中的函数。
通过修改 GOT 表项和绑定信息，实现符号级别的 Hook 功能。
"""

from typing import Annotated, Dict, Any, Optional
from pydantic import Field
import lief
import shutil

from .common import (
    create_backup_path,
    parse_macho,
    select_architecture_by_index,
    validate_file_path,
    write_macho,
)


def replace_macho_symbol(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    original_symbol: Annotated[str, Field(
        description="要替换的原始符号名称（标准C函数名，如 'malloc'），工具会自动添加下划线前缀进行查找"
    )],
    replacement_symbol: Annotated[str, Field(
        description="替换后的符号名称（标准C函数名，如 'my_malloc'），工具会自动添加下划线前缀"
    )],
    custom_dylib_name: Annotated[str, Field(
        description="自定义dylib的文件名，例如：'MyHook.dylib'。工具会自动构造为 @executable_path/Frameworks/{dylib_name} 格式"
    )],
    architecture_index: Annotated[int, Field(
        description="对于Fat Binary文件，指定要修改的架构索引（从0开始）。如果不指定，将修改第一个架构",
        ge=0
    )] = 0,
    backup_original: Annotated[bool, Field(
        description="是否在修改前备份原始文件。如果为True，将创建带时间戳的备份文件"
    )] = True
) -> Dict[str, Any]:
    """
    在 Mach-O 文件中替换符号绑定，将原始符号重定向到自定义 dylib 中的函数。
    
    该工具提供以下功能：
    - 查找并验证原始符号的绑定信息
    - 自动添加自定义 dylib 为依赖（如果尚未存在）
    - 修改符号绑定，将原始符号指向自定义 dylib 中的替换函数
    - 移除失效的代码签名
    - 提供详细的操作报告和修改前后对比
    
    支持单架构和 Fat Binary 文件的符号替换操作。
    """
    try:
        path_error = validate_file_path(file_path, require_write=True)
        if path_error:
            return path_error
        
        # 标准化符号名称（添加下划线前缀）
        internal_original = f"_{original_symbol}"
        internal_replacement = f"_{replacement_symbol}"
        dylib_path = f"@executable_path/Frameworks/{custom_dylib_name}"
        
        fat_binary, parse_error = parse_macho(file_path)
        if parse_error:
            return parse_error
        
        binary, arch_error = select_architecture_by_index(fat_binary, architecture_index)
        if arch_error:
            return arch_error
        
        # 备份原始文件
        backup_path = None
        if backup_original:
            try:
                backup_path = create_backup_path(
                    file_path,
                    suffix="backup",
                    separator=".",
                    timestamp_sep="_",
                    include_uuid=True,
                )
                shutil.copy2(file_path, backup_path)
            except Exception as e:
                return {
                    "error": f"备份文件失败: {str(e)}",
                    "suggestion": "请检查磁盘空间和权限，或设置 backup_original=False"
                }
        
        # 执行符号替换
        result = _perform_symbol_replacement(
            binary, 
            internal_original, 
            internal_replacement, 
            dylib_path,
            custom_dylib_name,
            architecture_index
        )
        
        if "error" in result:
            return result
        
        # 移除代码签名
        try:
            binary.remove_signature()
        except Exception as e:
            result["warnings"] = result.get("warnings", [])
            result["warnings"].append(f"移除代码签名时发生警告: {str(e)}")
        
        # 写入修改后的文件
        write_error = write_macho(fat_binary, file_path)
        if write_error:
            return {
                "error": write_error["error"],
                "suggestion": "请检查文件权限和磁盘空间",
                "backup_path": backup_path
            }
        
        # 构建成功结果
        result.update({
            "success": True,
            "file_path": file_path,
            "backup_path": backup_path,
            "architecture_index": architecture_index,
            "cpu_type": str(binary.header.cpu_type),
            "original_symbol": original_symbol,
            "replacement_symbol": replacement_symbol,
            "custom_dylib_name": custom_dylib_name,
            "dylib_path": dylib_path,
            "internal_original": internal_original,
            "internal_replacement": internal_replacement
        })
        
        return result
        
    except Exception as e:
        return {
            "error": f"符号替换过程中发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _perform_symbol_replacement(
    binary: lief.MachO.Binary, 
    internal_original: str, 
    internal_replacement: str, 
    dylib_path: str,
    custom_dylib_name: str,
    architecture_index: int
) -> Dict[str, Any]:
    """执行实际的符号替换操作"""
    
    result = {
        "operation_details": {
            "steps_completed": [],
            "binding_info": {},
            "dylib_info": {},
            "modification_summary": {}
        }
    }
    
    # 步骤1：查找原始符号的绑定信息
    original_binding = None
    original_library = None
    
    try:
        for binding in binary.bindings:
            if hasattr(binding, 'symbol') and binding.symbol:
                symbol_name = getattr(binding.symbol, 'name', '')
                if symbol_name == internal_original:
                    original_binding = binding
                    if hasattr(binding, 'library') and binding.library:
                        original_library = getattr(binding.library, 'name', '')
                    break
        
        if original_binding is None:
            return {
                "error": f"未找到符号 '{internal_original}' 的绑定信息",
                "suggestion": f"请确认符号 '{internal_original}' 确实被此二进制文件导入",
                "available_symbols": _get_available_imported_symbols(binary)[:10]  # 显示前10个可用符号
            }
        
        result["operation_details"]["steps_completed"].append("找到原始符号绑定信息")
        result["operation_details"]["binding_info"] = {
            "original_symbol": internal_original,
            "original_library": original_library,
            "binding_address": getattr(original_binding, 'address', 0),
            "binding_type": str(getattr(original_binding, 'type', 'UNKNOWN'))
        }
        
    except Exception as e:
        return {
            "error": f"查找原始符号绑定信息时发生错误: {str(e)}",
            "suggestion": "请检查二进制文件的绑定信息是否完整"
        }
    
    # 步骤2：检查并添加自定义 dylib 依赖
    dylib_exists = False
    dylib_ordinal = -1
    
    try:
        # 检查是否已存在该 dylib
        for i, library in enumerate(binary.libraries):
            lib_name = getattr(library, 'name', '')
            if dylib_path in lib_name or custom_dylib_name in lib_name:
                dylib_exists = True
                dylib_ordinal = i + 1  # 库序号从1开始
                break
        
        if not dylib_exists:
            # 添加新的 dylib 依赖
            try:
                binary.add_library(dylib_path)
                # 重新获取库序号
                for i, library in enumerate(binary.libraries):
                    lib_name = getattr(library, 'name', '')
                    if dylib_path in lib_name:
                        dylib_ordinal = i + 1
                        break
                
                result["operation_details"]["steps_completed"].append("添加自定义dylib依赖")
                result["operation_details"]["dylib_info"]["added_dependency"] = True
            except Exception as e:
                return {
                    "error": f"添加dylib依赖失败: {str(e)}",
                    "suggestion": "请检查dylib路径格式是否正确"
                }
        else:
            result["operation_details"]["steps_completed"].append("发现已存在的dylib依赖")
            result["operation_details"]["dylib_info"]["added_dependency"] = False
        
        result["operation_details"]["dylib_info"].update({
            "dylib_path": dylib_path,
            "dylib_ordinal": dylib_ordinal,
            "already_existed": dylib_exists
        })
        
    except Exception as e:
        return {
            "error": f"处理dylib依赖时发生错误: {str(e)}",
            "suggestion": "请检查二进制文件的库依赖信息"
        }
    
    # 步骤3：修改符号绑定
    binding_modified = False
    
    try:
        # 查找并修改绑定信息
        for binding in binary.bindings:
            if hasattr(binding, 'symbol') and binding.symbol:
                symbol_name = getattr(binding.symbol, 'name', '')
                if symbol_name == internal_original:
                    # 修改符号名称
                    if hasattr(binding.symbol, 'name'):
                        binding.symbol.name = internal_replacement
                    
                    # 修改库序号
                    if hasattr(binding, 'library_ordinal'):
                        binding.library_ordinal = dylib_ordinal
                    
                    # 如果有库对象，也要更新
                    if hasattr(binding, 'library') and dylib_ordinal <= len(binary.libraries):
                        try:
                            new_library = binary.libraries[dylib_ordinal - 1]
                            binding.library = new_library
                        except (IndexError, AttributeError):
                            pass  # 如果无法设置库对象，继续执行
                    
                    binding_modified = True
                    break
        
        if not binding_modified:
            return {
                "error": "无法修改符号绑定信息",
                "suggestion": "绑定信息可能是只读的或格式不支持修改"
            }
        
        result["operation_details"]["steps_completed"].append("修改符号绑定信息")
        result["operation_details"]["modification_summary"] = {
            "symbol_name_changed": f"{internal_original} -> {internal_replacement}",
            "library_changed": f"{original_library} -> {dylib_path}",
            "library_ordinal": dylib_ordinal
        }
        
    except Exception as e:
        return {
            "error": f"修改符号绑定时发生错误: {str(e)}",
            "suggestion": "请检查绑定信息是否支持修改"
        }
    
    # 步骤4：验证修改结果
    try:
        verification_result = _verify_symbol_replacement(binary, internal_replacement, dylib_ordinal)
        result["operation_details"]["verification"] = verification_result
        result["operation_details"]["steps_completed"].append("验证符号替换结果")
        
    except Exception as e:
        result["warnings"] = result.get("warnings", [])
        result["warnings"].append(f"验证修改结果时发生警告: {str(e)}")
    
    return result


def _get_available_imported_symbols(binary: lief.MachO.Binary) -> list:
    """获取可用的导入符号列表"""
    
    symbols = []
    try:
        for binding in binary.bindings:
            if hasattr(binding, 'symbol') and binding.symbol:
                symbol_name = getattr(binding.symbol, 'name', '')
                if symbol_name and symbol_name not in symbols:
                    symbols.append(symbol_name)
    except Exception:
        pass
    
    return sorted(symbols)


def _verify_symbol_replacement(binary: lief.MachO.Binary, replacement_symbol: str, expected_ordinal: int) -> Dict[str, Any]:
    """验证符号替换是否成功"""
    
    verification = {
        "replacement_symbol_found": False,
        "correct_library_ordinal": False,
        "binding_details": {}
    }
    
    try:
        for binding in binary.bindings:
            if hasattr(binding, 'symbol') and binding.symbol:
                symbol_name = getattr(binding.symbol, 'name', '')
                if symbol_name == replacement_symbol:
                    verification["replacement_symbol_found"] = True
                    
                    # 检查库序号
                    if hasattr(binding, 'library_ordinal'):
                        ordinal = getattr(binding, 'library_ordinal', -1)
                        verification["correct_library_ordinal"] = (ordinal == expected_ordinal)
                        verification["binding_details"]["library_ordinal"] = ordinal
                    
                    # 获取其他绑定详情
                    verification["binding_details"].update({
                        "address": getattr(binding, 'address', 0),
                        "type": str(getattr(binding, 'type', 'UNKNOWN')),
                        "addend": getattr(binding, 'addend', 0)
                    })
                    
                    # 获取库信息
                    if hasattr(binding, 'library') and binding.library:
                        lib_name = getattr(binding.library, 'name', '')
                        verification["binding_details"]["library_name"] = lib_name
                    
                    break
    
    except Exception as e:
        verification["error"] = f"验证过程中发生错误: {str(e)}"
    
    return verification


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
