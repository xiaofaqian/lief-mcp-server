"""
Mach-O 依赖动态库列表工具

此工具专门用于列出 Mach-O 文件中的所有依赖动态库信息，包括库名称、版本信息、加载类型等详细数据。
提供完整的库依赖分析，帮助理解二进制文件的动态链接依赖关系和库加载配置。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os
import re


def list_macho_libraries(
    file_path: Annotated[str, Field(
        description="Mach-O文件在系统中的完整绝对路径，例如：/Applications/MyApp.app/Contents/MacOS/MyApp 或 /usr/bin/ls 或 /bin/dyld"
    )],
    offset: Annotated[int, Field(
        description="起始位置偏移量，从第几个依赖库开始返回（从0开始计数）",
        ge=0
    )] = 0,
    count: Annotated[int, Field(
        description="返回的依赖库数量，最大100条，0表示返回所有剩余依赖库",
        ge=0,
        le=100
    )] = 20,
    name_filter: Annotated[Optional[str], Field(
        description="依赖库名称过滤器，支持正则表达式匹配。例如：'Foundation' 或 '^/usr/lib/.*' 或 '.*dylib$'"
    )] = None,
    include_analysis: Annotated[bool, Field(
        description="是否包含详细的库用途分析和特性说明"
    )] = True
) -> Dict[str, Any]:
    """
    列出 Mach-O 文件中的所有依赖动态库信息，包括库名称、版本、加载类型等详细数据。
    
    该工具解析 Mach-O 文件的库依赖结构，提供：
    - 依赖库完整路径和名称
    - 库的当前版本和兼容版本信息
    - 库加载命令类型（标准加载、弱加载、重导出等）
    - 库的用途分析和分类
    - 依赖关系统计和系统库识别
    
    支持单架构和 Fat Binary 文件的库依赖信息提取。
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
        
        # 遍历所有架构的库依赖信息
        for i, binary in enumerate(fat_binary):
            try:
                arch_libraries = _extract_libraries_info(binary, i, offset, count, name_filter, include_analysis)
                result["architectures"].append(arch_libraries)
            except Exception as e:
                result["architectures"].append({
                    "architecture_index": i,
                    "error": f"解析架构 {i} 库依赖信息时发生错误: {str(e)}"
                })
        
        return result
        
    except Exception as e:
        return {
            "error": f"解析文件库依赖信息时发生未预期的错误: {str(e)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持"
        }


def _extract_libraries_info(
    binary: lief.MachO.Binary, 
    index: int, 
    offset: int = 0, 
    count: int = 20, 
    name_filter: Optional[str] = None,
    include_analysis: bool = True
) -> Dict[str, Any]:
    """提取单个架构的库依赖详细信息，支持分页和过滤"""
    
    header = binary.header
    
    # 编译正则表达式过滤器
    regex_filter = None
    if name_filter:
        try:
            regex_filter = re.compile(name_filter, re.IGNORECASE)
        except re.error as e:
            return {
                "architecture_index": index,
                "error": f"正则表达式过滤器无效: {name_filter}, 错误: {str(e)}",
                "suggestion": "请检查正则表达式语法，例如：'^/usr/lib/.*' 或 '.*Foundation.*'"
            }
    
    # 收集所有库依赖信息
    all_libraries = []
    total_libraries_count = 0
    
    # 从库依赖中收集信息
    for library in binary.libraries:
        total_libraries_count += 1
        try:
            library_name = library.name
            
            # 应用名称过滤器
            if regex_filter and not regex_filter.search(library_name):
                continue
            
            library_info = _extract_single_library_info(library, include_analysis)
            all_libraries.append(library_info)
            
        except Exception as e:
            # 即使解析失败，也要检查是否符合过滤条件
            library_name = getattr(library, 'name', 'unknown')
            if not regex_filter or regex_filter.search(library_name):
                all_libraries.append({
                    "name": library_name,
                    "error": f"解析库依赖信息时发生错误: {str(e)}"
                })
    
    # 应用分页
    filtered_count = len(all_libraries)
    
    # 检查偏移量是否有效
    if offset >= filtered_count and filtered_count > 0:
        return {
            "architecture_index": index,
            "cpu_type": str(header.cpu_type),
            "cpu_subtype": str(header.cpu_subtype),
            "error": f"偏移量 {offset} 超出范围，过滤后的库依赖总数为 {filtered_count}",
            "suggestion": f"请使用 0 到 {max(0, filtered_count - 1)} 之间的偏移量"
        }
    
    # 计算实际返回的库依赖数量
    if count == 0:
        # 返回所有剩余库依赖
        end_index = filtered_count
    else:
        end_index = min(offset + count, filtered_count)
    
    paged_libraries = all_libraries[offset:end_index]
    
    # 基本架构信息
    arch_info = {
        "architecture_index": index,
        "cpu_type": str(header.cpu_type),
        "cpu_subtype": str(header.cpu_subtype),
        "pagination_info": {
            "total_libraries_in_binary": total_libraries_count,
            "filtered_libraries_count": filtered_count,
            "requested_offset": offset,
            "requested_count": count,
            "returned_count": len(paged_libraries),
            "has_more": end_index < filtered_count,
            "next_offset": end_index if end_index < filtered_count else None
        },
        "filter_info": {
            "name_filter": name_filter,
            "filter_applied": name_filter is not None,
            "filter_valid": regex_filter is not None
        },
        "libraries": paged_libraries
    }
    
    # 添加库依赖统计信息（基于所有过滤后的库依赖，不仅仅是当前页）
    if include_analysis:
        arch_info["library_statistics"] = _calculate_library_statistics(all_libraries)
    
    return arch_info


def _extract_single_library_info(library, include_analysis: bool = True) -> Dict[str, Any]:
    """提取单个库依赖的详细信息"""
    
    library_info = {
        "name": library.name,
        "current_version": _format_version(library.current_version),
        "compatibility_version": _format_version(library.compatibility_version),
        "timestamp": library.timestamp
    }
    
    # 添加加载命令类型信息
    try:
        command_type = str(library.command)
        library_info["command"] = {
            "type": command_type,
            "description": _get_load_command_description(command_type)
        }
        
        # 解析加载特性
        library_info["load_characteristics"] = _parse_load_characteristics(command_type)
        
    except Exception as e:
        library_info["command"] = {
            "error": f"无法获取加载命令信息: {str(e)}"
        }
    
    # 添加库路径分析
    library_info["path_analysis"] = _analyze_library_path(library.name)
    
    # 添加库用途分析
    if include_analysis:
        library_info["library_analysis"] = _analyze_library_purpose(library.name)
    
    # 添加版本兼容性分析
    library_info["version_analysis"] = _analyze_version_compatibility(
        library.current_version, 
        library.compatibility_version
    )
    
    return library_info


def _format_version(version) -> Dict[str, Any]:
    """格式化版本号为可读格式"""
    
    try:
        # 检查版本号的类型
        if isinstance(version, list) and len(version) >= 3:
            # LIEF 返回的是列表格式 [major, minor, patch]
            major, minor, patch = version[0], version[1], version[2]
            version_string = f"{major}.{minor}.{patch}"
            
            return {
                "raw": version,
                "formatted": version_string,
                "major": major,
                "minor": minor,
                "patch": patch
            }
        elif isinstance(version, int):
            # 传统的32位整数格式：XXXX.YY.ZZ
            major = (version >> 16) & 0xFFFF
            minor = (version >> 8) & 0xFF
            patch = version & 0xFF
            
            version_string = f"{major}.{minor}.{patch}"
            
            return {
                "raw": version,
                "formatted": version_string,
                "major": major,
                "minor": minor,
                "patch": patch
            }
        else:
            # 其他格式，直接转换为字符串
            return {
                "raw": version,
                "formatted": str(version),
                "major": 0,
                "minor": 0,
                "patch": 0
            }
    except Exception as e:
        return {
            "raw": version,
            "formatted": str(version),
            "error": f"版本号格式解析失败: {str(e)}"
        }


def _get_load_command_description(command_type: str) -> str:
    """获取加载命令类型的描述"""
    
    command_descriptions = {
        "LOAD_DYLIB": "标准动态库加载 - 程序启动时必须加载",
        "LOAD_WEAK_DYLIB": "弱动态库加载 - 库不存在时程序仍可运行",
        "REEXPORT_DYLIB": "重导出动态库 - 将库的符号重新导出给其他模块",
        "LOAD_UPWARD_DYLIB": "向上动态库加载 - 用于解决循环依赖",
        "LAZY_LOAD_DYLIB": "延迟动态库加载 - 首次使用时才加载"
    }
    
    # 提取命令类型名称（去掉可能的前缀）
    clean_command = command_type.split('.')[-1] if '.' in command_type else command_type
    
    return command_descriptions.get(clean_command, f"未知加载命令类型: {command_type}")


def _parse_load_characteristics(command_type: str) -> Dict[str, Any]:
    """解析库加载特性"""
    
    characteristics = {
        "is_required": True,
        "is_weak": False,
        "is_reexport": False,
        "is_upward": False,
        "is_lazy": False,
        "load_timing": "启动时加载",
        "failure_behavior": "加载失败时程序无法启动"
    }
    
    clean_command = command_type.split('.')[-1] if '.' in command_type else command_type
    
    if "WEAK" in clean_command:
        characteristics.update({
            "is_required": False,
            "is_weak": True,
            "failure_behavior": "加载失败时程序仍可继续运行"
        })
    
    if "REEXPORT" in clean_command:
        characteristics.update({
            "is_reexport": True,
            "load_timing": "启动时加载并重导出符号"
        })
    
    if "UPWARD" in clean_command:
        characteristics.update({
            "is_upward": True,
            "load_timing": "用于解决循环依赖的特殊加载"
        })
    
    if "LAZY" in clean_command:
        characteristics.update({
            "is_lazy": True,
            "load_timing": "首次使用时才加载"
        })
    
    return characteristics


def _analyze_library_path(library_path: str) -> Dict[str, Any]:
    """分析库路径信息"""
    
    analysis = {
        "full_path": library_path,
        "directory": os.path.dirname(library_path),
        "filename": os.path.basename(library_path),
        "extension": os.path.splitext(library_path)[1],
        "is_system_path": False,
        "is_framework": False,
        "path_type": "未知路径类型"
    }
    
    # 分析路径类型
    if library_path.startswith('/usr/lib/'):
        analysis.update({
            "is_system_path": True,
            "path_type": "系统库路径",
            "description": "标准系统动态库目录"
        })
    elif library_path.startswith('/System/Library/'):
        analysis.update({
            "is_system_path": True,
            "path_type": "系统框架路径",
            "description": "macOS/iOS 系统框架目录"
        })
        if '/Frameworks/' in library_path:
            analysis["is_framework"] = True
    elif library_path.startswith('/Library/Frameworks/'):
        analysis.update({
            "is_framework": True,
            "path_type": "第三方框架路径",
            "description": "第三方安装的框架目录"
        })
    elif library_path.startswith('@'):
        # 处理相对路径标记
        if library_path.startswith('@executable_path/'):
            analysis.update({
                "path_type": "可执行文件相对路径",
                "description": "相对于可执行文件的路径"
            })
        elif library_path.startswith('@loader_path/'):
            analysis.update({
                "path_type": "加载器相对路径",
                "description": "相对于加载该库的模块的路径"
            })
        elif library_path.startswith('@rpath/'):
            analysis.update({
                "path_type": "运行时搜索路径",
                "description": "使用运行时搜索路径解析"
            })
    elif library_path.startswith('/opt/'):
        analysis.update({
            "path_type": "可选软件路径",
            "description": "第三方软件安装目录"
        })
    elif library_path.startswith('/usr/local/'):
        analysis.update({
            "path_type": "本地安装路径",
            "description": "用户本地安装的软件目录"
        })
    else:
        analysis.update({
            "path_type": "自定义路径",
            "description": "非标准路径位置"
        })
    
    # 分析文件扩展名
    if analysis["extension"] == '.dylib':
        analysis["file_type"] = "动态链接库"
    elif analysis["extension"] == '.framework':
        analysis["file_type"] = "框架包"
        analysis["is_framework"] = True
    else:
        analysis["file_type"] = "未知文件类型"
    
    return analysis


def _analyze_library_purpose(library_path: str) -> Dict[str, Any]:
    """分析库的用途和特性"""
    
    analysis = {
        "purpose": "未知用途",
        "category": "第三方库",
        "characteristics": [],
        "common_functions": [],
        "framework_type": None
    }
    
    library_name = os.path.basename(library_path).lower()
    path_lower = library_path.lower()
    
    # 系统库分析
    if library_path.startswith('/usr/lib/') or library_path.startswith('/System/'):
        analysis["category"] = "系统库"
        
        # 核心系统库
        if 'libc' in library_name or 'libsystem' in library_name:
            analysis.update({
                "purpose": "C标准库和系统调用",
                "common_functions": ["malloc", "free", "printf", "open", "read", "write"],
                "characteristics": ["核心系统库", "必需依赖"]
            })
        elif 'libobjc' in library_name:
            analysis.update({
                "purpose": "Objective-C运行时库",
                "common_functions": ["objc_msgSend", "class_getName", "sel_registerName"],
                "characteristics": ["运行时库", "Objective-C支持"]
            })
        elif 'libdispatch' in library_name:
            analysis.update({
                "purpose": "Grand Central Dispatch并发库",
                "common_functions": ["dispatch_async", "dispatch_queue_create"],
                "characteristics": ["并发处理", "异步执行"]
            })
        
        # 系统框架
        elif 'foundation' in path_lower:
            analysis.update({
                "purpose": "Foundation框架 - Objective-C基础类",
                "framework_type": "基础框架",
                "common_functions": ["NSString", "NSArray", "NSDictionary", "NSObject"],
                "characteristics": ["基础数据类型", "集合类", "字符串处理"]
            })
        elif 'uikit' in path_lower:
            analysis.update({
                "purpose": "UIKit框架 - iOS用户界面",
                "framework_type": "UI框架",
                "common_functions": ["UIView", "UIViewController", "UIButton", "UILabel"],
                "characteristics": ["iOS UI", "视图控制", "用户交互"]
            })
        elif 'appkit' in path_lower:
            analysis.update({
                "purpose": "AppKit框架 - macOS用户界面",
                "framework_type": "UI框架",
                "common_functions": ["NSView", "NSViewController", "NSButton", "NSTextField"],
                "characteristics": ["macOS UI", "窗口管理", "用户交互"]
            })
        elif 'corefoundation' in path_lower:
            analysis.update({
                "purpose": "Core Foundation - C语言基础框架",
                "framework_type": "基础框架",
                "common_functions": ["CFString", "CFArray", "CFDictionary"],
                "characteristics": ["C语言API", "基础数据类型", "跨平台"]
            })
        elif 'security' in path_lower:
            analysis.update({
                "purpose": "安全框架 - 加密和认证",
                "framework_type": "安全框架",
                "common_functions": ["SecKeychain", "SecCertificate", "SecTrust"],
                "characteristics": ["加密解密", "证书管理", "安全认证"]
            })
        elif 'network' in path_lower:
            analysis.update({
                "purpose": "网络框架",
                "framework_type": "网络框架",
                "common_functions": ["URLSession", "Socket", "HTTP"],
                "characteristics": ["网络通信", "HTTP请求", "套接字"]
            })
        elif 'coredata' in path_lower:
            analysis.update({
                "purpose": "Core Data - 数据持久化框架",
                "framework_type": "数据框架",
                "common_functions": ["NSManagedObject", "NSPersistentStore"],
                "characteristics": ["数据持久化", "对象关系映射", "数据库操作"]
            })
        elif 'coregraphics' in path_lower:
            analysis.update({
                "purpose": "Core Graphics - 2D图形绘制",
                "framework_type": "图形框架",
                "common_functions": ["CGContext", "CGPath", "CGImage"],
                "characteristics": ["2D绘图", "图像处理", "PDF生成"]
            })
        elif 'quartzcore' in path_lower:
            analysis.update({
                "purpose": "Quartz Core - 动画和合成",
                "framework_type": "图形框架",
                "common_functions": ["CALayer", "CAAnimation"],
                "characteristics": ["图层动画", "视觉效果", "硬件加速"]
            })
        elif 'avfoundation' in path_lower:
            analysis.update({
                "purpose": "AV Foundation - 音视频处理",
                "framework_type": "媒体框架",
                "common_functions": ["AVPlayer", "AVAsset", "AVCaptureSession"],
                "characteristics": ["音频处理", "视频播放", "媒体捕获"]
            })
    
    # 第三方库分析
    else:
        analysis["category"] = "第三方库"
        
        # 常见第三方库识别
        if 'sqlite' in library_name:
            analysis.update({
                "purpose": "SQLite数据库引擎",
                "characteristics": ["嵌入式数据库", "SQL支持"]
            })
        elif 'ssl' in library_name or 'crypto' in library_name:
            analysis.update({
                "purpose": "SSL/TLS加密库",
                "characteristics": ["网络加密", "证书验证"]
            })
        elif 'curl' in library_name:
            analysis.update({
                "purpose": "HTTP客户端库",
                "characteristics": ["HTTP请求", "文件传输"]
            })
        elif 'xml' in library_name:
            analysis.update({
                "purpose": "XML解析库",
                "characteristics": ["XML处理", "文档解析"]
            })
        elif 'json' in library_name:
            analysis.update({
                "purpose": "JSON处理库",
                "characteristics": ["JSON解析", "数据序列化"]
            })
    
    # 路径特性分析
    if library_path.startswith('@'):
        analysis["characteristics"].append("相对路径引用")
    
    if '.framework' in library_path:
        analysis["characteristics"].append("框架包")
        analysis["is_framework"] = True
    elif library_path.endswith('.dylib'):
        analysis["characteristics"].append("动态链接库")
    
    return analysis


def _analyze_version_compatibility(current_version, compatibility_version) -> Dict[str, Any]:
    """分析版本兼容性"""
    
    try:
        current_formatted = _format_version(current_version)
        compat_formatted = _format_version(compatibility_version)
        
        # 转换版本号为可比较的数值
        def version_to_number(version):
            if isinstance(version, list) and len(version) >= 3:
                return version[0] * 10000 + version[1] * 100 + version[2]
            elif isinstance(version, int):
                return version
            else:
                return 0
        
        current_num = version_to_number(current_version)
        compat_num = version_to_number(compatibility_version)
        
        analysis = {
            "current_version": current_formatted,
            "compatibility_version": compat_formatted,
            "is_compatible": current_num >= compat_num,
            "version_difference": current_num - compat_num
        }
        
        # 兼容性分析
        if current_num == compat_num:
            analysis["compatibility_status"] = "版本完全匹配"
            analysis["compatibility_risk"] = "无风险"
        elif current_num > compat_num:
            analysis["compatibility_status"] = "向后兼容"
            analysis["compatibility_risk"] = "低风险"
            
            # 检查版本差异程度
            current_major = current_formatted.get("major", 0)
            compat_major = compat_formatted.get("major", 0)
            
            if current_major > compat_major:
                analysis["compatibility_risk"] = "中等风险 - 主版本号不同"
        else:
            analysis["compatibility_status"] = "版本不兼容"
            analysis["compatibility_risk"] = "高风险 - 当前版本低于要求"
        
        # 版本建议
        if analysis["is_compatible"]:
            analysis["recommendation"] = "版本兼容，可以正常使用"
        else:
            analysis["recommendation"] = f"需要升级到至少 {compat_formatted['formatted']} 版本"
        
        return analysis
        
    except Exception as e:
        # 如果版本分析失败，返回基本信息
        return {
            "current_version": {"raw": current_version, "formatted": str(current_version)},
            "compatibility_version": {"raw": compatibility_version, "formatted": str(compatibility_version)},
            "is_compatible": True,
            "version_difference": 0,
            "error": f"版本分析失败: {str(e)}"
        }


def _calculate_library_statistics(libraries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算库依赖统计信息"""
    
    stats = {
        "total_libraries": len(libraries),
        "system_libraries": 0,
        "third_party_libraries": 0,
        "frameworks": 0,
        "dylibs": 0,
        "load_types": {},
        "path_types": {},
        "weak_libraries": 0,
        "reexport_libraries": 0,
        "lazy_libraries": 0,
        "upward_libraries": 0,
        "version_analysis": {
            "libraries_with_versions": 0,
            "compatible_libraries": 0,
            "version_mismatches": 0
        },
        "top_directories": {},
        "framework_types": {},
        "library_categories": {}
    }
    
    for library in libraries:
        if "error" in library:
            continue
        
        # 统计系统库 vs 第三方库
        if "path_analysis" in library:
            if library["path_analysis"].get("is_system_path", False):
                stats["system_libraries"] += 1
            else:
                stats["third_party_libraries"] += 1
            
            # 统计文件类型
            if library["path_analysis"].get("is_framework", False):
                stats["frameworks"] += 1
            elif library["path_analysis"].get("extension") == ".dylib":
                stats["dylibs"] += 1
            
            # 统计路径类型
            path_type = library["path_analysis"].get("path_type", "未知")
            stats["path_types"][path_type] = stats["path_types"].get(path_type, 0) + 1
            
            # 统计顶级目录
            directory = library["path_analysis"].get("directory", "")
            if directory:
                stats["top_directories"][directory] = stats["top_directories"].get(directory, 0) + 1
        
        # 统计加载类型
        if "command" in library and "type" in library["command"]:
            load_type = library["command"]["type"]
            stats["load_types"][load_type] = stats["load_types"].get(load_type, 0) + 1
        
        # 统计加载特性
        if "load_characteristics" in library:
            chars = library["load_characteristics"]
            if chars.get("is_weak", False):
                stats["weak_libraries"] += 1
            if chars.get("is_reexport", False):
                stats["reexport_libraries"] += 1
            if chars.get("is_lazy", False):
                stats["lazy_libraries"] += 1
            if chars.get("is_upward", False):
                stats["upward_libraries"] += 1
        
        # 统计库分析信息
        if "library_analysis" in library:
            analysis = library["library_analysis"]
            
            # 统计库分类
            category = analysis.get("category", "未知")
            stats["library_categories"][category] = stats["library_categories"].get(category, 0) + 1
            
            # 统计框架类型
            framework_type = analysis.get("framework_type")
            if framework_type:
                stats["framework_types"][framework_type] = stats["framework_types"].get(framework_type, 0) + 1
        
        # 统计版本信息
        if "version_analysis" in library:
            version_analysis = library["version_analysis"]
            stats["version_analysis"]["libraries_with_versions"] += 1
            
            if version_analysis.get("is_compatible", False):
                stats["version_analysis"]["compatible_libraries"] += 1
            else:
                stats["version_analysis"]["version_mismatches"] += 1
    
    # 转换为列表格式以便显示（取前10个）
    stats["top_directories"] = sorted(stats["top_directories"].items(), key=lambda x: x[1], reverse=True)[:10]
    
    return stats
