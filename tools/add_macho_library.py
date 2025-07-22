"""
Mach-O 添加依赖库工具

此工具用于向 Mach-O 文件中添加新的依赖动态库。
支持相对路径格式（@executable_path、@loader_path、@rpath）和绝对路径。
"""

from typing import Annotated, Dict, Any, Optional
from pydantic import Field
import lief
import os
import shutil
from datetime import datetime


def add_macho_library(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    library_path: Annotated[str, Field(
        description="要添加的动态库路径，支持相对路径格式如：@executable_path/Frameworks/libname.dylib、@loader_path/lib/libname.dylib、@rpath/libname.dylib 或绝对路径如：/usr/lib/libSystem.B.dylib"
    )],
    architecture_index: Annotated[Optional[int], Field(
        description="对于Fat Binary文件，指定要修改的架构索引（从0开始）。如果不指定，将修改第一个架构"
    )] = 0,
    output_path: Annotated[Optional[str], Field(
        description="输出文件的完整绝对路径。如果不指定，将覆盖原文件"
    )] = None,
    backup_original: Annotated[bool, Field(
        description="是否备份原始文件。如果为True，将创建带时间戳的备份文件"
    )] = True
) -> Dict[str, Any]:
    """
    向 Mach-O 文件添加动态库依赖，支持相对路径格式。

    该工具提供以下功能：
    - 向 Mach-O 文件添加新的动态库依赖
    - 支持相对路径格式（@executable_path、@loader_path、@rpath）
    - 支持单架构和 Fat Binary 文件
    - 自动处理加载命令的添加
    - 可选的原文件备份功能
    - 验证库路径格式的有效性

    支持的路径格式：
    - @executable_path/Frameworks/libname.dylib（相对于可执行文件）
    - @loader_path/lib/libname.dylib（相对于加载器）
    - @rpath/libname.dylib（运行时搜索路径）
    - /usr/lib/libname.dylib（绝对路径）
    """
    
    result = {
        "success": False,
        "message": "",
        "file_info": {},
        "library_info": {},
        "backup_path": None,
        "output_path": output_path or file_path
    }
    
    try:
        # 验证输入文件
        if not os.path.exists(file_path):
            result["message"] = f"文件不存在: {file_path}"
            return result
        
        if not os.access(file_path, os.R_OK):
            result["message"] = f"无权限读取文件: {file_path}"
            return result
        
        # 验证库路径格式
        if not library_path.strip():
            result["message"] = "库路径不能为空"
            return result
        
        # 验证路径格式的有效性
        path_validation = _validate_library_path(library_path)
        if not path_validation["valid"]:
            result["message"] = f"库路径格式无效: {path_validation['error']}"
            result["suggestion"] = path_validation["suggestion"]
            return result
        
        # 备份原文件
        if backup_original:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{file_path}.backup_{timestamp}"
            try:
                shutil.copy2(file_path, backup_path)
                result["backup_path"] = backup_path
            except Exception as e:
                result["message"] = f"备份文件失败: {str(e)}"
                return result
        
        # 解析 Mach-O 文件
        try:
            fat_binary = lief.MachO.parse(file_path)
            if fat_binary is None:
                result["message"] = "无法解析 Mach-O 文件，可能文件格式不正确"
                return result
        except Exception as e:
            result["message"] = f"解析文件失败: {str(e)}"
            return result
        
        # 获取文件信息
        result["file_info"] = {
            "is_fat_binary": len(fat_binary) > 1,
            "architecture_count": len(fat_binary),
            "architectures": []
        }
        
        # 验证架构索引
        if architecture_index >= len(fat_binary):
            result["message"] = f"架构索引 {architecture_index} 超出范围，文件只有 {len(fat_binary)} 个架构"
            return result
        
        # 获取目标架构
        target_binary = fat_binary[architecture_index]
        
        # 记录架构信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_info = {
                    "index": i,
                    "cpu_type": str(binary.header.cpu_type),
                    "cpu_subtype": str(binary.header.cpu_subtype),
                    "is_target": i == architecture_index
                }
                result["file_info"]["architectures"].append(arch_info)
            except Exception as e:
                result["file_info"]["architectures"].append({
                    "index": i,
                    "error": f"获取架构信息失败: {str(e)}"
                })
        
        # 检查库是否已存在
        existing_libraries = []
        for lib in target_binary.libraries:
            try:
                existing_libraries.append(lib.name)
                if lib.name == library_path:
                    result["message"] = f"库 {library_path} 已存在于架构 {architecture_index} 中"
                    result["library_info"] = {
                        "already_exists": True,
                        "existing_library": {
                            "name": lib.name,
                            "current_version": _format_version_simple(lib.current_version),
                            "compatibility_version": _format_version_simple(lib.compatibility_version),
                            "command_type": str(lib.command)
                        }
                    }
                    return result
            except Exception as e:
                # 忽略单个库的解析错误，继续处理
                continue
        
        # 添加新库
        try:
            # 使用 LIEF 的 add_library 方法
            added_library = target_binary.add_library(library_path)
            
            # 记录添加的库信息
            result["library_info"] = {
                "added_library": {
                    "name": library_path,
                    "path_type": path_validation["path_type"],
                    "description": path_validation["description"],
                    "current_version": _format_version_simple(added_library.current_version),
                    "compatibility_version": _format_version_simple(added_library.compatibility_version),
                    "command_type": str(added_library.command)
                },
                "total_libraries_before": len(existing_libraries),
                "total_libraries_after": len(existing_libraries) + 1
            }
            
        except Exception as e:
            result["message"] = f"添加库失败: {str(e)}"
            return result
        
        # 移除代码签名（修改后需要重新签名）
        try:
            fat_binary.remove_signature()
        except Exception as e:
            # 移除签名失败通常不是致命错误，记录警告
            result["warning"] = f"移除代码签名时发生警告: {str(e)}"
        
        # 写入文件
        try:
            output_file = output_path or file_path
            fat_binary.write(output_file)
            result["output_path"] = output_file
        except Exception as e:
            result["message"] = f"写入修改后的文件失败: {str(e)}"
            return result
        
        # 成功
        result["success"] = True
        result["message"] = f"成功向 {file_path} 的架构 {architecture_index} 添加库依赖: {library_path}"
        
        return result
        
    except Exception as e:
        result["message"] = f"添加库依赖时发生未预期的错误: {str(e)}"
        return result


def _validate_library_path(library_path: str) -> Dict[str, Any]:
    """验证库路径格式的有效性"""
    
    validation = {
        "valid": False,
        "path_type": "未知",
        "description": "",
        "error": "",
        "suggestion": ""
    }
    
    # 检查空路径
    if not library_path or not library_path.strip():
        validation.update({
            "error": "库路径不能为空",
            "suggestion": "请提供有效的库路径，例如：@executable_path/Frameworks/libname.dylib"
        })
        return validation
    
    library_path = library_path.strip()
    
    # 检查相对路径格式
    if library_path.startswith('@executable_path/'):
        validation.update({
            "valid": True,
            "path_type": "可执行文件相对路径",
            "description": "相对于可执行文件的路径，运行时解析为可执行文件所在目录"
        })
        
        # 验证路径结构
        relative_part = library_path[len('@executable_path/'):]
        if not relative_part:
            validation.update({
                "valid": False,
                "error": "@executable_path/ 后缺少相对路径",
                "suggestion": "例如：@executable_path/Frameworks/libname.dylib"
            })
        elif not relative_part.endswith('.dylib') and not relative_part.endswith('.framework'):
            validation.update({
                "valid": False,
                "error": "库路径应以 .dylib 或 .framework 结尾",
                "suggestion": "例如：@executable_path/Frameworks/libname.dylib"
            })
    
    elif library_path.startswith('@loader_path/'):
        validation.update({
            "valid": True,
            "path_type": "加载器相对路径",
            "description": "相对于加载该库的模块的路径"
        })
        
        relative_part = library_path[len('@loader_path/'):]
        if not relative_part:
            validation.update({
                "valid": False,
                "error": "@loader_path/ 后缺少相对路径",
                "suggestion": "例如：@loader_path/lib/libname.dylib"
            })
        elif not relative_part.endswith('.dylib') and not relative_part.endswith('.framework'):
            validation.update({
                "valid": False,
                "error": "库路径应以 .dylib 或 .framework 结尾",
                "suggestion": "例如：@loader_path/lib/libname.dylib"
            })
    
    elif library_path.startswith('@rpath/'):
        validation.update({
            "valid": True,
            "path_type": "运行时搜索路径",
            "description": "使用运行时搜索路径解析，需要在可执行文件中设置 rpath"
        })
        
        relative_part = library_path[len('@rpath/'):]
        if not relative_part:
            validation.update({
                "valid": False,
                "error": "@rpath/ 后缺少库名",
                "suggestion": "例如：@rpath/libname.dylib"
            })
        elif not relative_part.endswith('.dylib') and not relative_part.endswith('.framework'):
            validation.update({
                "valid": False,
                "error": "库路径应以 .dylib 或 .framework 结尾",
                "suggestion": "例如：@rpath/libname.dylib"
            })
    
    elif library_path.startswith('/'):
        # 绝对路径
        validation.update({
            "valid": True,
            "path_type": "绝对路径",
            "description": "系统绝对路径"
        })
        
        # 检查常见的系统路径
        if library_path.startswith('/usr/lib/'):
            validation["description"] = "系统库路径 - 标准系统动态库目录"
        elif library_path.startswith('/System/Library/'):
            validation["description"] = "系统框架路径 - macOS/iOS 系统框架目录"
        elif library_path.startswith('/Library/Frameworks/'):
            validation["description"] = "第三方框架路径 - 第三方安装的框架目录"
        elif library_path.startswith('/opt/'):
            validation["description"] = "可选软件路径 - 第三方软件安装目录"
        elif library_path.startswith('/usr/local/'):
            validation["description"] = "本地安装路径 - 用户本地安装的软件目录"
        
        # 检查文件扩展名
        if not library_path.endswith('.dylib') and not library_path.endswith('.framework') and '/Frameworks/' not in library_path:
            validation.update({
                "valid": False,
                "error": "绝对路径应指向 .dylib 文件或框架",
                "suggestion": "例如：/usr/lib/libSystem.B.dylib 或 /System/Library/Frameworks/Foundation.framework/Foundation"
            })
    
    else:
        # 无效的路径格式
        validation.update({
            "error": "不支持的路径格式",
            "suggestion": "支持的格式：@executable_path/、@loader_path/、@rpath/ 或绝对路径（以/开头）"
        })
    
    return validation


def _format_version_simple(version) -> str:
    """简单格式化版本号"""
    
    try:
        if isinstance(version, list) and len(version) >= 3:
            return f"{version[0]}.{version[1]}.{version[2]}"
        elif isinstance(version, int):
            major = (version >> 16) & 0xFFFF
            minor = (version >> 8) & 0xFF
            patch = version & 0xFF
            return f"{major}.{minor}.{patch}"
        else:
            return str(version)
    except Exception:
        return str(version)
