"""
Mach-O 移除依赖库工具

此工具用于从 Mach-O 文件中移除指定的依赖动态库。
"""

from typing import Annotated, Dict, Any
from pydantic import Field
import lief
import os
import shutil
from datetime import datetime


def remove_macho_library(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    library_name: Annotated[str, Field(
        description="要移除的依赖库的完整名称，例如：@rpath/libExample.dylib 或 /usr/lib/libSystem.B.dylib"
    )],
    backup_original: Annotated[bool, Field(
        description="是否在修改前备份原始文件",
        default=True
    )] = True
) -> Dict[str, Any]:
    """
    从 Mach-O 文件中移除指定的依赖库。

    该工具会：
    1. 解析指定的 Mach-O 文件
    2. 查找并移除指定名称的依赖库
    3. 移除失效的代码签名
    4. 将修改后的文件写回原路径
    5. （可选）在修改前创建原始文件的备份

    Args:
        file_path: Mach-O 文件的完整绝对路径
        library_name: 要移除的依赖库的完整名称
        backup_original: 是否备份原始文件，默认为 True

    Returns:
        包含操作结果的字典
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
        
        if not os.access(file_path, os.W_OK):
            return {
                "error": f"无权限写入文件: {file_path}",
                "suggestion": "请检查文件权限，确保当前用户有写入权限"
            }
        
        # 创建备份
        if backup_original:
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                backup_path = f"{file_path}.backup.{timestamp}"
                shutil.copy2(file_path, backup_path)
            except Exception as e:
                return {
                    "error": f"创建备份文件时发生错误: {str(e)}",
                    "suggestion": "请检查磁盘空间和目录写入权限"
                }
        
        # 解析 Mach-O 文件
        try:
            fat_binary = lief.MachO.parse(file_path)
            if fat_binary is None:
                return {
                    "error": "无法解析文件，可能不是有效的 Mach-O 文件",
                    "file_path": file_path,
                    "suggestion": "请确认文件是有效的 Mach-O 格式文件"
                }
        except Exception as e:
            return {
                "error": f"解析 Mach-O 文件时发生错误: {str(e)}",
                "file_path": file_path,
                "suggestion": "文件可能已损坏或格式不支持"
            }
        
        # 标记是否找到并移除了库
        library_removed = False
        removed_library_info = None
        
        # 遍历所有架构
        for i, binary in enumerate(fat_binary):
            try:
                # 查找要移除的库
                target_library = None
                for lib in binary.libraries:
                    if lib.name == library_name:
                        target_library = lib
                        break
                
                if target_library is None:
                    continue  # 在此架构中未找到，继续下一个
                
                # 移除库
                binary.remove(target_library)
                library_removed = True
                removed_library_info = {
                    "architecture_index": i,
                    "library_name": library_name,
                    "command_type": str(target_library.command),
                    "current_version": target_library.current_version,
                    "compatibility_version": target_library.compatibility_version
                }
                break  # 找到并移除后，跳出循环
                
            except Exception as e:
                return {
                    "error": f"处理架构 {i} 时发生错误: {str(e)}",
                    "architecture_index": i
                }
        
        # 检查是否成功移除了库
        if not library_removed:
            return {
                "error": f"未找到指定的依赖库: {library_name}",
                "file_path": file_path,
                "suggestion": "请检查库名称是否正确，可以使用 list_macho_libraries 工具查看文件中的所有依赖库"
            }
        
        # 移除代码签名
        try:
            fat_binary.remove_signature()
        except Exception as e:
            # 移除签名失败通常不是致命错误，可以记录警告
            print(f"警告: 移除代码签名时发生警告: {str(e)}")
        
        # 写回文件
        try:
            fat_binary.write(file_path)
        except Exception as e:
            return {
                "error": f"写入修改后的文件时发生错误: {str(e)}",
                "suggestion": "请检查磁盘空间和文件权限"
            }
        
        # 返回成功结果
        return {
            "success": True,
            "message": f"成功从 {file_path} 中移除依赖库: {library_name}",
            "file_path": file_path,
            "removed_library": removed_library_info,
            "backup_created": backup_original
        }
        
    except Exception as e:
        return {
            "error": f"移除依赖库时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }
