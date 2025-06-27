"""
移除MachO二进制文件符号的MCP工具
"""
from typing import Dict, Any, Annotated
from pydantic import Field
import lief
import os


def remove_macho_symbol(
    file_path: Annotated[str, Field(
        description="MachO二进制文件在系统中的完整绝对路径，例如：/Users/username/Documents/app.app/Contents/MacOS/app 或 /Applications/MyApp.app/Contents/MacOS/MyApp"
    )],
    symbol_name: Annotated[str, Field(
        description="要移除的符号名称"
    )]
) -> Dict[str, Any]:
    """
    从MachO二进制文件中移除指定的符号。
    
    此工具可以安全地从MachO格式的二进制文件中移除指定符号，
    包括函数符号、变量符号等。工具会自动执行安全检查，
    确保移除操作不会损坏二进制文件的完整性。
    
    安全机制：
    - 自动检查符号是否可以安全移除
    - 拒绝移除系统关键符号
    - 验证移除操作的成功性
    
    注意事项：
    - 移除成功后会直接覆盖原文件
    - 建议在操作前手动备份重要文件
    - 仅支持MachO格式的二进制文件
    """
    try:
        # 验证文件路径
        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "error": "无效的文件路径参数"
            }
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return {
                "success": False,
                "error": f"文件不存在: {file_path}"
            }
        
        # 检查文件权限
        if not os.access(file_path, os.R_OK | os.W_OK):
            return {
                "success": False,
                "error": f"没有读写权限: {file_path}"
            }
        
        # 验证符号名称
        if not symbol_name or not isinstance(symbol_name, str):
            return {
                "success": False,
                "error": "无效的符号名称参数"
            }
        
        # 解析二进制文件
        binary = lief.parse(file_path)
        if binary is None:
            return {
                "success": False,
                "error": "无法解析文件，可能不是有效的二进制文件"
            }
        
        # 检查是否为MachO格式
        if binary.format != lief.Binary.FORMATS.MACHO:
            return {
                "success": False,
                "error": f"不支持的文件格式: {binary.format.name}，此工具仅支持MachO格式"
            }
        
        # 处理MachO FAT二进制文件
        if hasattr(binary, 'at') and callable(binary.at):
            binary = binary.at(0)
        
        # 检查符号是否存在（移除前验证）
        symbol_exists_before = False
        target_symbol = None
        
        for symbol in binary.symbols:
            if symbol.name == symbol_name:
                symbol_exists_before = True
                target_symbol = symbol
                break
        
        if not symbol_exists_before:
            return {
                "success": False,
                "error": f"符号 '{symbol_name}' 在文件中不存在"
            }
        
        # 执行安全检查
        try:
            can_remove = binary.can_remove_symbol(symbol_name)
            if not can_remove:
                return {
                    "success": False,
                    "error": f"符号 '{symbol_name}' 无法安全移除，可能是系统关键符号或被其他符号依赖"
                }
        except AttributeError:
            # 如果LIEF版本不支持can_remove_symbol，我们进行基本检查
            # 检查是否为关键系统符号
            critical_symbols = [
                "_main", "main", "_start", "start", 
                "_dyld_start", "__dyld_start",
                "_exit", "_abort", "__stack_chk_fail"
            ]
            if symbol_name in critical_symbols:
                return {
                    "success": False,
                    "error": f"符号 '{symbol_name}' 是关键系统符号，不能移除"
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"安全检查失败: {str(e)}"
            }
        
        # 执行符号移除
        try:
            # 尝试使用remove_symbol方法
            if hasattr(binary, 'remove_symbol'):
                removal_success = binary.remove_symbol(symbol_name)
            else:
                # 如果没有remove_symbol方法，尝试直接移除符号对象
                if target_symbol and hasattr(binary, 'remove'):
                    removal_success = binary.remove(target_symbol)
                else:
                    return {
                        "success": False,
                        "error": "当前LIEF版本不支持符号移除操作"
                    }
            
            if not removal_success:
                return {
                    "success": False,
                    "error": f"符号 '{symbol_name}' 移除操作失败，可能存在内部依赖"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"符号移除过程中发生错误: {str(e)}"
            }
        
        # 保存修改后的文件（覆盖原文件）
        try:
            binary.write(file_path)
        except Exception as e:
            return {
                "success": False,
                "error": f"保存文件失败: {str(e)}"
            }
        
        # 验证移除结果
        try:
            # 重新解析文件验证
            verification_binary = lief.parse(file_path)
            if verification_binary is None:
                return {
                    "success": False,
                    "error": "文件保存后验证失败，文件可能已损坏"
                }
            
            # 处理FAT二进制
            if hasattr(verification_binary, 'at') and callable(verification_binary.at):
                verification_binary = verification_binary.at(0)
            
            # 检查符号是否已被移除
            symbol_exists_after = False
            for symbol in verification_binary.symbols:
                if symbol.name == symbol_name:
                    symbol_exists_after = True
                    break
            
            if symbol_exists_after:
                return {
                    "success": False,
                    "error": f"符号移除验证失败，符号 '{symbol_name}' 仍然存在于文件中"
                }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"移除结果验证失败: {str(e)}"
            }
        
        # 返回成功结果
        return {
            "success": True,
            "file_path": file_path,
            "symbol_name": symbol_name,
            "removed": True,
            "verification": {
                "symbol_exists_before": symbol_exists_before,
                "symbol_exists_after": False
            },
            "message": f"符号 '{symbol_name}' 已成功从文件中移除"
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
    except Exception as e:
        return {
            "success": False,
            "error": f"移除符号时发生未预期的错误: {str(e)}"
        }
