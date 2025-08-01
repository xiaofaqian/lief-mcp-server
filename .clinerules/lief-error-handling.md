## Brief overview
这些规则记录了在使用 LIEF 库开发 MCP 工具时遇到的具体错误和解决方案，特别是针对枚举对象处理、类型转换等问题的最佳实践。这是基于实际开发经验总结的项目特定规则。

## LIEF 枚举对象处理错误
- 避免直接将 LIEF 枚举对象（如 section.flags）转换为整数，会导致 "'FLAGS' object cannot be interpreted as an integer" 错误
- 使用 try-catch 块安全处理枚举对象：先尝试 int() 转换，失败时使用 str() 获取字符串表示
- 对于标志位字段，提供多种表示方式：数值、十六进制、字符串描述
- 示例处理模式：
  ```python
  try:
      flags_value = int(section.flags)
      flags_hex = hex(flags_value)
  except (TypeError, ValueError):
      flags_value = str(section.flags)
      flags_hex = "N/A"
  ```

## 错误处理策略
- 为每个可能失败的 LIEF 操作添加异常处理，避免单个解析错误导致整个工具失败
- 在解析集合对象（如 segments、sections）时，对每个元素单独处理异常
- 提供有意义的错误信息，包含具体的错误原因和上下文
- 使用渐进式错误处理：先处理能成功的部分，再报告失败的部分

## 类型安全实践
- 在访问 LIEF 对象属性前使用 hasattr() 检查属性是否存在
- 对于可能不存在的属性提供默认值或跳过处理
- 避免假设所有 Mach-O 文件都有相同的属性结构
- 使用 getattr() 函数安全获取属性值，提供默认值

## 调试和验证方法
- 在开发新工具时先用已知的二进制文件（如 /bin/ls）进行测试
- 使用简单的 Python 脚本验证 LIEF 对象的实际类型和属性
- 逐步添加功能，每次只处理一个属性或字段
- 在遇到类型错误时，使用 type() 和 str() 函数探索对象的实际结构

## 代码复用和一致性
- 参考现有工具的实现方式，特别是枚举对象的处理方法
- 保持一致的错误处理模式和返回结构
- 复用已验证的辅助函数，如安全的类型转换和描述映射
- 在添加新工具前检查现有工具的实现模式，避免重复相同的错误
