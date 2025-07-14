# LIEF MCP 服务器开发指南

## 项目概述

本项目是一个基于 Model Context Protocol (MCP) 的 LIEF 二进制分析服务器，提供统一的接口来分析 ELF、PE、Mach-O 等二进制文件格式。

## 项目结构

```
lief-mcp-server/
├── server.py                    # 主服务器文件
├── requirements.txt             # 依赖包列表
├── tools/                       # 工具目录
│   ├── __init__.py             # 工具包初始化
│   └── parse_macho_info.py     # Mach-O 信息解析工具
├── LIEF_Documentation_Summary.md      # LIEF 文档总结
├── LIEF_ELF_PE_Documentation.md       # ELF/PE 格式文档
└── Development_Guide.md               # 开发指南（本文件）
```

## 开发规范

### 1. 工具开发规范

#### 1.1 文件命名
- 工具文件名使用下划线分隔的小写命名：`tool_name.py`
- 工具函数名与文件名保持一致：`tool_name`
- 每个工具一个独立文件

#### 1.2 代码结构
```python
"""
工具描述

详细说明工具的功能、用途和使用场景。
"""

from typing import Annotated, Dict, Any, List, Optional
from pydantic import Field
import lief
import os


def tool_name(
    parameter: Annotated[type, Field(
        description="参数描述，必须包含完整绝对路径示例"
    )]
) -> Dict[str, Any]:
    """
    工具功能的详细描述
    
    支持的功能：
    - 功能1
    - 功能2
    - 功能3
    
    返回结构化的分析结果。
    """
    try:
        # 参数验证
        if not os.path.exists(parameter):
            return {
                "error": f"文件不存在: {parameter}",
                "suggestion": "请检查文件路径是否正确"
            }
        
        # 主要逻辑
        result = perform_analysis(parameter)
        
        return result
        
    except Exception as e:
        return {
            "error": f"处理时发生错误: {str(e)}",
            "suggestion": "请检查文件格式或联系技术支持"
        }


def _helper_function():
    """辅助函数使用下划线前缀"""
    pass
```

#### 1.3 参数规范
- 使用 `Annotated` 和 `Field` 进行参数标注
- 文件路径参数必须说明需要"完整绝对路径"
- 提供具体的路径示例
- 包含不同操作系统的路径格式

#### 1.4 错误处理
- 统一的错误返回格式
- 包含 `error` 和 `suggestion` 字段
- 详细的错误信息和解决建议
- 文件路径验证和权限检查

### 2. 工具注册流程

#### 2.1 创建工具文件
在 `tools/` 目录下创建新的工具文件：
```bash
touch tools/new_tool.py
```

#### 2.2 实现工具函数
按照上述规范实现工具函数。

#### 2.3 更新 __init__.py
在 `tools/__init__.py` 中添加导入和注册：
```python
# 导入工具函数
from .new_tool import new_tool

# 更新 __all__ 列表
__all__ = [
    "parse_macho_info",
    "new_tool",  # 新增
]

# 更新 TOOLS 列表
TOOLS = [
    parse_macho_info,
    new_tool,  # 新增
]
```

#### 2.4 测试工具
启动服务器测试工具是否正确注册：
```bash
python server.py
```

## 建议的工具开发路线图

### 阶段 1：基础信息工具
- [x] `parse_macho_info` - Mach-O 基本信息解析
- [ ] `parse_elf_info` - ELF 基本信息解析
- [ ] `parse_pe_info` - PE 基本信息解析
- [ ] `detect_binary_format` - 二进制格式检测

### 阶段 2：符号分析工具
- [ ] `list_symbols` - 列出符号表
- [ ] `search_symbol` - 搜索特定符号
- [ ] `analyze_imports` - 分析导入函数
- [ ] `analyze_exports` - 分析导出函数

### 阶段 3：结构分析工具
- [ ] `list_sections` - 列出节信息
- [ ] `list_segments` - 列出段信息
- [ ] `analyze_dependencies` - 依赖关系分析
- [ ] `extract_strings` - 提取字符串

### 阶段 4：高级分析工具
- [ ] `disassemble_function` - 反汇编函数
- [ ] `analyze_objc_metadata` - Objective-C 元数据分析
- [ ] `check_security_features` - 安全特性检查
- [ ] `compare_binaries` - 二进制文件比较

### 阶段 5：修改工具
- [ ] `patch_binary` - 二进制补丁
- [ ] `inject_library` - 库注入
- [ ] `modify_entrypoint` - 修改入口点
- [ ] `strip_signatures` - 移除签名

## 工具模板

### 通用信息解析工具模板
```python
def parse_format_info(
    file_path: Annotated[str, Field(
        description="二进制文件在系统中的完整绝对路径，例如：/usr/bin/ls 或 C:\\Windows\\System32\\kernel32.dll"
    )]
) -> Dict[str, Any]:
    """解析二进制文件的基本信息"""
    
    try:
        # 文件验证
        if not os.path.exists(file_path):
            return {"error": f"文件不存在: {file_path}"}
        
        # 解析文件
        binary = lief.parse(file_path)
        if binary is None:
            return {"error": "无法解析文件"}
        
        # 提取信息
        result = {
            "file_path": file_path,
            "format": binary.format.name,
            "architecture": str(binary.header.machine_type),
            "entrypoint": hex(binary.entrypoint),
            # ... 其他信息
        }
        
        return result
        
    except Exception as e:
        return {"error": f"解析错误: {str(e)}"}
```

### 列表查询工具模板
```python
def list_format_items(
    file_path: Annotated[str, Field(description="文件路径描述")],
    filter_pattern: Annotated[Optional[str], Field(
        description="可选的过滤模式，支持正则表达式"
    )] = None,
    limit: Annotated[Optional[int], Field(
        description="返回结果的最大数量，默认为100"
    )] = 100
) -> Dict[str, Any]:
    """列出文件中的特定项目"""
    
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return {"error": "无法解析文件"}
        
        items = []
        count = 0
        
        for item in binary.items:
            if filter_pattern and not re.match(filter_pattern, item.name):
                continue
            
            if limit and count >= limit:
                break
            
            items.append({
                "name": item.name,
                "value": item.value,
                # ... 其他属性
            })
            count += 1
        
        return {
            "file_path": file_path,
            "total_found": count,
            "items": items,
            "truncated": limit and count >= limit
        }
        
    except Exception as e:
        return {"error": f"查询错误: {str(e)}"}
```

### 搜索工具模板
```python
def search_format_item(
    file_path: Annotated[str, Field(description="文件路径描述")],
    search_term: Annotated[str, Field(
        description="搜索关键词，支持正则表达式"
    )],
    case_sensitive: Annotated[bool, Field(
        description="是否区分大小写"
    )] = False
) -> Dict[str, Any]:
    """搜索文件中的特定项目"""
    
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return {"error": "无法解析文件"}
        
        results = []
        flags = 0 if case_sensitive else re.IGNORECASE
        
        for item in binary.items:
            if re.search(search_term, item.name, flags):
                results.append({
                    "name": item.name,
                    "match_type": "name",
                    "value": item.value
                })
        
        return {
            "file_path": file_path,
            "search_term": search_term,
            "results_count": len(results),
            "results": results
        }
        
    except Exception as e:
        return {"error": f"搜索错误: {str(e)}"}
```

## 测试指南

### 1. 单元测试
为每个工具创建测试用例：
```python
def test_tool_name():
    # 测试正常情况
    result = tool_name("/valid/path")
    assert "error" not in result
    
    # 测试错误情况
    result = tool_name("/invalid/path")
    assert "error" in result
```

### 2. 集成测试
测试工具在 MCP 服务器中的集成：
```bash
# 启动服务器
python server.py

# 使用 MCP 客户端测试工具
```

### 3. 性能测试
测试大文件的处理性能：
```python
import time

start_time = time.time()
result = tool_name("/path/to/large/file")
end_time = time.time()

print(f"处理时间: {end_time - start_time:.2f} 秒")
```

## 最佳实践

### 1. 错误处理
- 始终使用 try-catch 包装主要逻辑
- 提供有意义的错误信息
- 包含解决建议

### 2. 性能优化
- 对于大文件，考虑分页处理
- 使用适当的解析配置
- 及时释放内存资源

### 3. 用户体验
- 提供进度指示（对于长时间操作）
- 返回结构化的数据
- 包含汇总信息

### 4. 安全考虑
- 验证文件路径
- 检查文件权限
- 防止路径遍历攻击

## 调试技巧

### 1. 日志记录
```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def tool_name(file_path):
    logger.debug(f"开始处理文件: {file_path}")
    # ... 处理逻辑
    logger.debug("处理完成")
```

### 2. LIEF 调试
```python
from lief import Logger
Logger.set_level(lief.LEVEL.DEBUG)
```

### 3. 异常详情
```python
import traceback

try:
    # 处理逻辑
    pass
except Exception as e:
    return {
        "error": str(e),
        "traceback": traceback.format_exc()
    }
```

## 部署指南

### 1. 依赖管理
确保 `requirements.txt` 包含所有必要的依赖：
```
mcp[cli]>=1.10.0
lief>=0.16.0
pydantic>=2.0.0
capstone>=5.0.0
pwntools>=4.8.0
```

### 2. 环境配置
```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate     # Windows

# 安装依赖
pip install -r requirements.txt
```

### 3. 服务器启动
```bash
python server.py
```

---

*本指南提供了完整的开发流程和最佳实践，帮助您高效地开发新的二进制分析工具。*
