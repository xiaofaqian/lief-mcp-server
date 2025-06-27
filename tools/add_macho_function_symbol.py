"""
为 mach-o 文件添加函数符号的 MCP 工具
"""
from typing import Dict, Any, Annotated
from pydantic import Field
import lief
import re


def add_macho_function_symbol(
    file_path: Annotated[str, Field(
        description="mach-o 文件在系统中的完整绝对路径，例如：/Users/username/Documents/app.app/Contents/MacOS/app 或 /Applications/MyApp.app/Contents/MacOS/MyApp"
    )],
    symbol_name: Annotated[str, Field(
        description="要添加的函数符号名称"
    )],
    address: Annotated[str, Field(
        description="函数的虚拟地址（与IDA中显示的地址一致），支持十六进制格式(如0x10007FD20)或十进制格式。工具会自动将虚拟地址转换为RVA进行内部处理"
    )]
) -> Dict[str, Any]:
    """
    为 mach-o 文件中的指定虚拟地址添加函数符号。
    
    此工具专门用于 mach-o 格式的二进制文件，接受虚拟地址（与IDA等工具显示一致）
    作为输入，自动转换为RVA后添加函数符号。工具会验证地址的有效性，确保地址
    位于有效的代码段范围内，并检查符号名称是否已存在。
    
    功能特性：
    - 仅支持 mach-o 格式文件
    - 接受虚拟地址输入，自动转换为RVA
    - 添加函数类型的导出符号
    - 验证地址是否在__TEXT段范围内
    - 检查符号名称冲突
    - 修改成功后覆盖原文件
    
    地址处理：
    - 输入：虚拟地址（如IDA中显示的0x10007FD20）
    - 内部处理：自动转换为RVA（如0x7FD20）
    - 存储：使用RVA创建符号
    
    注意事项：
    - 如果符号名称已存在，将返回错误
    - 地址必须在有效的代码段(__TEXT段)范围内
    - 修改后的文件将直接覆盖原文件
    """
    try:
        # 验证文件路径
        if not file_path or not isinstance(file_path, str):
            return {
                "success": False,
                "error": "无效的文件路径参数"
            }
        
        # 验证符号名称
        if not symbol_name or not isinstance(symbol_name, str):
            return {
                "success": False,
                "error": "无效的符号名称参数"
            }
        
        # 解析地址
        parsed_address = _parse_address(address)
        if parsed_address is None:
            return {
                "success": False,
                "error": f"无效的地址格式: {address}"
            }
        
        # 解析二进制文件
        binary = lief.parse(file_path)
        if binary is None:
            return {
                "success": False,
                "error": "无法解析文件，可能不是有效的二进制文件"
            }
        
        # 验证是否为 mach-o 格式
        if binary.format != lief.Binary.FORMATS.MACHO:
            return {
                "success": False,
                "error": f"文件格式不支持，需要 mach-o 格式，当前格式: {binary.format.name}"
            }
        
        # 处理 FAT 二进制文件，取第一个架构
        if hasattr(binary, 'at') and callable(binary.at):
            binary = binary.at(0)
        
        # 检查符号名称是否已存在
        if _symbol_exists(binary, symbol_name):
            return {
                "success": False,
                "error": f"符号名称已存在: {symbol_name}"
            }
        
        # 添加函数符号
        result = _add_function_symbol(binary, symbol_name, parsed_address)
        if not result["success"]:
            return {
                "success": False,
                "error": f"添加函数符号失败: {result['error']}"
            }
        
        # 保存文件
        binary.write(file_path)
        
        # 验证符号是否成功添加
        verification_binary = lief.parse(file_path)
        if hasattr(verification_binary, 'at') and callable(verification_binary.at):
            verification_binary = verification_binary.at(0)
        
        if not _symbol_exists(verification_binary, symbol_name):
            return {
                "success": False,
                "error": "符号添加后验证失败，可能保存过程中出现问题"
            }
        
        return {
            "success": True,
            "file_path": file_path,
            "symbol_name": symbol_name,
            "address": hex(parsed_address),  # 显示原始虚拟地址
            "rva": hex(result.get("address_conversion", {}).get("rva", 0)),  # 显示转换后的RVA
            "message": "函数符号添加成功",
            "details": {
                "export_added": result.get("export_added", False),
                "symbol_added": result.get("symbol_added", False),
                "method_used": result.get("method_used", "未知方法"),
                "address_conversion": result.get("address_conversion", {})
            }
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
            "error": f"添加函数符号时发生错误: {str(e)}"
        }


def _parse_address(address_str: str) -> int:
    """解析地址字符串，支持十六进制和十进制格式"""
    try:
        address_str = address_str.strip()
        
        # 十六进制格式
        if address_str.startswith('0x') or address_str.startswith('0X'):
            return int(address_str, 16)
        
        # 纯十六进制格式（无0x前缀）
        if re.match(r'^[0-9a-fA-F]+$', address_str):
            return int(address_str, 16)
        
        # 十进制格式
        if address_str.isdigit():
            return int(address_str, 10)
        
        return None
        
    except ValueError:
        return None


def _symbol_exists(binary, symbol_name: str) -> bool:
    """检查符号名称是否已存在"""
    try:
        # 检查所有符号
        for symbol in binary.symbols:
            if symbol.name == symbol_name:
                return True
        
        # 检查导出符号
        for symbol in binary.exported_symbols:
            if symbol.name == symbol_name:
                return True
        
        return False
        
    except Exception:
        return False


def _convert_va_to_rva(binary, virtual_address: int) -> Dict[str, Any]:
    """将虚拟地址转换为相对虚拟地址(RVA)"""
    try:
        # 查找包含该地址的段
        target_segment = None
        for segment in binary.segments:
            if segment.virtual_address <= virtual_address < (segment.virtual_address + segment.virtual_size):
                target_segment = segment
                break
        
        if target_segment is None:
            return {
                "success": False,
                "error": f"地址 {hex(virtual_address)} 不在任何有效段中"
            }
        
        # 计算RVA
        rva = virtual_address - target_segment.virtual_address
        
        # 验证是否在可执行段中（通常是__TEXT段）
        is_executable = hasattr(target_segment, 'flags') and (target_segment.flags & 0x4) != 0
        is_text_segment = target_segment.name == "__TEXT"
        
        if not is_text_segment:
            return {
                "success": False,
                "error": f"地址 {hex(virtual_address)} 不在__TEXT段中，当前段: {target_segment.name}"
            }
        
        return {
            "success": True,
            "rva": rva,
            "segment_name": target_segment.name,
            "segment_base": target_segment.virtual_address,
            "is_executable": is_executable
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"地址转换失败: {str(e)}"
        }


def _add_function_symbol(binary, symbol_name: str, virtual_address: int) -> Dict[str, Any]:
    """添加函数符号到二进制文件"""
    try:
        # 将虚拟地址转换为RVA
        conversion_result = _convert_va_to_rva(binary, virtual_address)
        if not conversion_result["success"]:
            return {
                "success": False,
                "error": f"地址转换失败: {conversion_result['error']}"
            }
        
        rva = conversion_result["rva"]
        
        # 首先尝试直接添加导出符号
        export_added = False
        symbol_added = False
        
        # 方法1：尝试使用 add_exported_function
        try:
            if hasattr(binary, 'add_exported_function'):
                export_info = binary.add_exported_function(rva, symbol_name)
                if export_info is not None:
                    export_added = True
                    symbol_added = True
        except Exception as e:
            pass  # 继续尝试其他方法
        
        # 方法2：如果导出函数添加失败，尝试手动创建导出符号
        if not export_added:
            try:
                # 找到 __TEXT 段中的 __text 节
                text_section = None
                text_section_index = 0
                for segment in binary.segments:
                    if segment.name == "__TEXT":
                        for section in segment.sections:
                            if section.name == "__text":
                                text_section = section
                                text_section_index = section.index
                                break
                        break
                
                if text_section is None:
                    return {
                        "success": False,
                        "error": "找不到 __TEXT.__text 节，无法添加函数符号"
                    }
                
                # 创建一个新的符号
                symbol = lief.MachO.Symbol()
                symbol.name = symbol_name
                symbol.value = rva  # 使用RVA而不是虚拟地址
                symbol.type = lief.MachO.Symbol.TYPE.SECTION  # 设置为 SECTION 类型
                symbol.numberof_sections = text_section_index + 1  # 节索引（从1开始）
                symbol.description = 0  # 清除描述字段
                
                # 添加符号到符号表
                binary.add_symbol(symbol)
                symbol_added = True
                
                # 尝试添加到导出信息
                try:
                    # 创建导出信息
                    export_info = lief.MachO.ExportInfo()
                    export_info.name = symbol_name
                    export_info.address = rva  # 使用RVA
                    export_info.flags = lief.MachO.ExportInfo.FLAGS.KIND_REGULAR
                    
                    # 添加到二进制文件的导出信息中
                    binary.add_exported_function(export_info.address, export_info.name)
                    export_added = True
                    
                except Exception as e:
                    # 如果导出信息添加失败，尝试修改符号属性
                    try:
                        # 将符号标记为外部可见
                        symbol.description &= ~0x0020  # 清除 N_PEXT 标志
                        symbol.description |= 0x0001   # 设置 N_EXT 标志（外部符号）
                        export_added = True
                    except Exception:
                        pass  # 导出表添加失败，但符号已添加
                
            except Exception as e:
                return {
                    "success": False,
                    "error": f"手动创建符号失败: {str(e)}"
                }
        
        # 方法3：如果以上都失败，使用 add_local_symbol 作为后备
        if not symbol_added:
            try:
                symbol = binary.add_local_symbol(rva, symbol_name)  # 使用RVA
                if symbol is not None:
                    symbol_added = True
                    # 尝试修改符号属性使其成为导出符号
                    try:
                        symbol.type = lief.MachO.Symbol.TYPE.SECTION
                        symbol.binding = lief.MachO.Symbol.BINDING.GLOBAL
                    except Exception:
                        pass
            except Exception as e:
                return {
                    "success": False,
                    "error": f"添加本地符号失败: {str(e)}"
                }
        
        if not symbol_added:
            return {
                "success": False,
                "error": "所有添加符号的方法都失败了"
            }
        
        return {
            "success": True,
            "export_added": export_added,
            "symbol_added": symbol_added,
            "method_used": "导出符号" if export_added else "本地符号（已尝试设置为全局）",
            "address_conversion": conversion_result
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"创建符号时发生错误: {str(e)}"
        }
