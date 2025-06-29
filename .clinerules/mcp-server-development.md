## Brief overview
这些规则专门针对 MCP (Model Context Protocol) 服务器工具开发，确保工具方法的标准化描述、参数规范化和异常处理的最佳实践。

## 工具方法文档规范
- 所有工具方法必须使用三个双引号（"""）包裹方法描述
- 方法描述应该清晰说明工具的功能、用途和预期行为
- 描述格式应遵循标准的 Python docstring 规范

## 参数处理规范
- 当方法有参数时，必须使用 `Annotated` 类型注解将参数规范化
- 参数注解应包含类型信息和详细的描述说明
- 使用 `Annotated[类型, Field(description="参数描述")]` 的格式进行参数标注
- 必须导入 `pydantic.Field` 来定义参数

## 文件组织结构
- 每个 MCP 工具必须放在一个单独的文件中
- 所有工具文件必须放在 `tools/` 目录下
- 工具方法的名字和文件名必须保持一致
- 文件名使用下划线分隔的小写命名（snake_case）

## 命名约定
- 工具文件名格式：`{tool_name}.py`
- 工具方法名格式：`{tool_name}`
- 确保文件名和方法名完全匹配，便于维护和查找

## 目录结构要求
- 在 `tools/` 目录下包含 `__init__.py` 文件
- 每个工具文件独立导入所需的依赖
- 保持工具之间的独立性，避免相互依赖

## 工具导入规范
- 所有工具的导入必须统一放在 `tools/__init__.py` 文件中
- 使用相对导入方式从各个工具模块导入函数：`from .tool_name import tool_name`
- 在 `__init__.py` 中定义 `__all__` 列表，明确导出的工具函数
- 创建 `TOOLS` 列表，包含所有工具函数的引用，便于动态注册
- 主服务器文件通过 `from tools import TOOLS` 导入工具列表

## 工具注册规范
- 在主服务器文件中统一注册所有工具
- 使用动态导入方式加载工具模块
- 通过循环遍历 `TOOLS` 列表进行批量注册：`for tool in TOOLS: mcp.tool()(tool)`
- 确保工具注册的一致性和可维护性

## 异常处理要求
- 实现严格的异常处理机制
- 捕获并处理所有可能的异常情况
- 提供有意义的错误信息和适当的错误响应
- 确保异常不会导致整个 MCP 服务器崩溃

## 代码质量标准
- 遵循 Python PEP 8 编码规范
- 确保代码的可读性和可维护性
- 添加适当的类型提示以提高代码质量
