# LIEF ELF 和 PE 格式文档补充

## ELF 格式分析

### 1. ELF 基础解析

```python
import lief

# 解析 ELF 文件
elf = lief.ELF.parse("/usr/bin/ls")

# 基本信息
print(f"架构: {elf.header.machine_type}")
print(f"文件类型: {elf.header.file_type}")
print(f"入口点: {hex(elf.header.entrypoint)}")
print(f"类别: {elf.header.identity_class}")  # 32位或64位
```

### 2. ELF 段和节

```python
# 遍历段 (Segments)
for segment in elf.segments:
    print(f"段类型: {segment.type}")
    print(f"虚拟地址: {hex(segment.virtual_address)}")
    print(f"文件偏移: {segment.file_offset}")
    print(f"大小: {segment.virtual_size}")

# 遍历节 (Sections)
for section in elf.sections:
    print(f"节名: {section.name}")
    print(f"类型: {section.type}")
    print(f"虚拟地址: {hex(section.virtual_address)}")
    print(f"大小: {section.size}")
    print(f"内容长度: {len(section.content)}")
```

### 3. ELF 符号表

```python
# 静态符号
for symbol in elf.static_symbols:
    print(f"符号名: {symbol.name}")
    print(f"值: {hex(symbol.value)}")
    print(f"大小: {symbol.size}")
    print(f"类型: {symbol.type}")

# 动态符号
for symbol in elf.dynamic_symbols:
    print(f"符号名: {symbol.name}")
    print(f"值: {hex(symbol.value)}")

# 导入的符号
for symbol in elf.imported_symbols:
    print(f"导入符号: {symbol.name}")

# 导出的函数
for func in elf.exported_functions:
    print(f"导出函数: {func}")
```

### 4. ELF 动态信息

```python
# 动态条目
for entry in elf.dynamic_entries:
    print(f"标签: {entry.tag}")
    print(f"值: {entry.value}")
    
    # 特定类型的处理
    if isinstance(entry, lief.ELF.DynamicEntryLibrary):
        print(f"依赖库: {entry.name}")
    elif isinstance(entry, lief.ELF.DynamicEntryRpath):
        print(f"运行时路径: {entry.rpath}")

# 重定位信息
for relocation in elf.relocations:
    print(f"地址: {hex(relocation.address)}")
    print(f"类型: {relocation.type}")
    if relocation.has_symbol:
        print(f"符号: {relocation.symbol.name}")
```

### 5. ELF 修改操作

```python
# 添加节
new_section = lief.ELF.Section(".custom", lief.ELF.SECTION_TYPES.PROGBITS)
new_section.content = [0x90] * 100  # NOP 指令
elf.add(new_section)

# 添加段
segment = lief.ELF.Segment()
segment.type = lief.ELF.SEGMENT_TYPES.LOAD
segment.add(new_section)
elf.add(segment)

# 修改入口点
elf.header.entrypoint = 0x401000

# 添加库依赖
elf.add_library("libcustom.so")

# 写入文件
elf.write("modified.elf")
```

### 6. ELF 特殊功能

```python
# 检查是否为 PIE
if hasattr(elf, 'is_pie'):
    print(f"是否为 PIE: {elf.is_pie}")

# GNU 版本信息
for version in elf.symbols_version:
    print(f"版本: {version}")

# GNU 哈希表
if elf.use_gnu_hash:
    gnu_hash = elf.gnu_hash
    print(f"GNU 哈希桶数: {gnu_hash.nb_buckets}")

# 注释信息
for note in elf.notes:
    print(f"注释名: {note.name}")
    print(f"类型: {note.type}")
    print(f"描述: {note.description}")
```

## PE 格式分析

### 1. PE 基础解析

```python
import lief

# 解析 PE 文件
pe = lief.PE.parse("C:\\Windows\\System32\\kernel32.dll")

# 基本头部信息
print(f"DOS 头: {pe.dos_header}")
print(f"PE 头: {pe.header}")
print(f"可选头: {pe.optional_header}")

# 基本属性
print(f"架构: {pe.header.machine}")
print(f"入口点: {hex(pe.optional_header.addressof_entrypoint)}")
print(f"镜像基址: {hex(pe.optional_header.imagebase)}")
```

### 2. PE 节信息

```python
# 遍历节
for section in pe.sections:
    print(f"节名: {section.name}")
    print(f"虚拟地址: {hex(section.virtual_address)}")
    print(f"虚拟大小: {section.virtual_size}")
    print(f"原始大小: {section.sizeof_raw_data}")
    print(f"特征: {section.characteristics}")
    print(f"内容: {len(section.content)} 字节")

# 获取特定节
text_section = pe.get_section(".text")
if text_section:
    print(f"代码节大小: {text_section.virtual_size}")
```

### 3. PE 导入表

```python
# 遍历导入的库
for imported_lib in pe.imports:
    print(f"库名: {imported_lib.name}")
    
    # 遍历导入的函数
    for func in imported_lib.entries:
        if not func.is_ordinal:
            print(f"  函数名: {func.name}")
            print(f"  IAT 地址: {hex(func.iat_address)}")
        else:
            print(f"  序号: {func.ordinal}")
```

### 4. PE 导出表

```python
# 检查是否有导出表
if pe.has_exports:
    exports = pe.get_export()
    print(f"导出库名: {exports.name}")
    
    # 遍历导出的函数
    for entry in exports.entries:
        print(f"函数名: {entry.name}")
        print(f"序号: {entry.ordinal}")
        print(f"地址: {hex(entry.address)}")
```

### 5. PE 资源

```python
# 检查资源
if pe.has_resources:
    resources = pe.resources
    
    def print_resources(node, level=0):
        indent = "  " * level
        if node.has_name:
            print(f"{indent}名称: {node.name}")
        else:
            print(f"{indent}ID: {node.id}")
        
        if node.is_directory:
            for child in node.childs:
                print_resources(child, level + 1)
        else:
            print(f"{indent}数据大小: {len(node.content)}")
    
    print_resources(resources)
```

### 6. PE 重定位

```python
# 重定位信息
for relocation in pe.relocations:
    print(f"虚拟地址: {hex(relocation.virtual_address)}")
    print(f"块大小: {relocation.block_size}")
    
    for entry in relocation.entries:
        print(f"  偏移: {entry.offset}")
        print(f"  类型: {entry.type}")
```

### 7. PE 异常处理

```python
# 异常目录
if pe.has_exceptions:
    for exception in pe.exceptions:
        print(f"开始地址: {hex(exception.begin_address)}")
        print(f"结束地址: {hex(exception.end_address)}")
        print(f"展开信息: {hex(exception.unwind_info_address)}")
```

### 8. PE 调试信息

```python
# 调试目录
if pe.has_debug:
    for debug in pe.debug:
        print(f"类型: {debug.type}")
        print(f"时间戳: {debug.timestamp}")
        print(f"数据大小: {debug.sizeof_data}")

# CodeView 调试信息
if hasattr(pe, 'codeview_pdb') and pe.codeview_pdb:
    pdb = pe.codeview_pdb
    print(f"PDB 文件名: {pdb.filename}")
    print(f"GUID: {pdb.guid}")
    print(f"年龄: {pdb.age}")
```

### 9. PE 数字签名

```python
# 检查数字签名
if pe.has_signatures:
    for signature in pe.signatures:
        print(f"版本: {signature.version}")
        print(f"摘要算法: {signature.digest_algorithm}")
        
        # 签名者信息
        for signer in signature.signers:
            print(f"签名者: {signer.issuer}")
            print(f"序列号: {signer.serial_number}")
            
            # 证书信息
            cert = signer.cert
            print(f"证书主题: {cert.subject}")
            print(f"证书颁发者: {cert.issuer}")
            print(f"有效期从: {cert.valid_from}")
            print(f"有效期到: {cert.valid_to}")

# 验证签名
verification_flags = pe.verify_signature()
print(f"签名验证结果: {verification_flags}")
```

### 10. PE 修改操作

```python
# 添加节
new_section = lief.PE.Section(".custom")
new_section.content = [0x90] * 1000
new_section.characteristics = (
    lief.PE.SECTION_CHARACTERISTICS.CNT_CODE |
    lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE |
    lief.PE.SECTION_CHARACTERISTICS.MEM_READ
)
pe.add_section(new_section)

# 添加导入
kernel32 = pe.add_library("kernel32.dll")
kernel32.add_entry("GetCurrentProcess")

# 修改入口点
pe.optional_header.addressof_entrypoint = 0x2000

# 写入文件
pe.write("modified.exe")
```

## 通用工具函数

### 1. 格式检测

```python
def detect_format(file_path):
    """检测文件格式"""
    try:
        # 尝试解析为不同格式
        if lief.ELF.parse(file_path):
            return "ELF"
        elif lief.PE.parse(file_path):
            return "PE"
        elif lief.MachO.parse(file_path):
            return "Mach-O"
        else:
            return "Unknown"
    except:
        return "Error"
```

### 2. 通用信息提取

```python
def extract_basic_info(file_path):
    """提取文件基本信息"""
    binary = lief.parse(file_path)
    if binary is None:
        return None
    
    info = {
        "format": binary.format.name,
        "architecture": str(binary.header.machine_type) if hasattr(binary.header, 'machine_type') else "Unknown",
        "entrypoint": hex(binary.entrypoint),
        "imported_functions": [f for f in binary.imported_functions],
        "exported_functions": [f for f in binary.exported_functions],
    }
    
    return info
```

### 3. 符号搜索

```python
def search_symbol(binary, symbol_name):
    """搜索符号"""
    results = []
    
    # 搜索静态符号
    if hasattr(binary, 'static_symbols'):
        for symbol in binary.static_symbols:
            if symbol_name in symbol.name:
                results.append({
                    "type": "static",
                    "name": symbol.name,
                    "value": hex(symbol.value),
                    "size": symbol.size
                })
    
    # 搜索动态符号
    if hasattr(binary, 'dynamic_symbols'):
        for symbol in binary.dynamic_symbols:
            if symbol_name in symbol.name:
                results.append({
                    "type": "dynamic",
                    "name": symbol.name,
                    "value": hex(symbol.value)
                })
    
    return results
```

### 4. 依赖分析

```python
def analyze_dependencies(binary):
    """分析依赖关系"""
    dependencies = []
    
    if binary.format == lief.Binary.FORMATS.ELF:
        for entry in binary.dynamic_entries:
            if isinstance(entry, lief.ELF.DynamicEntryLibrary):
                dependencies.append(entry.name)
    
    elif binary.format == lief.Binary.FORMATS.PE:
        for imported_lib in binary.imports:
            dependencies.append(imported_lib.name)
    
    elif binary.format == lief.Binary.FORMATS.MACHO:
        for lib in binary.libraries:
            dependencies.append(lib.name)
    
    return dependencies
```

## 性能优化建议

### 1. 解析配置

```python
# ELF 快速解析
elf_config = lief.ELF.ParserConfig()
elf_config.parse_relocations = False
elf_config.parse_dynamic_symbols = False

# PE 快速解析
pe_config = lief.PE.ParserConfig()
pe_config.parse_imports = False
pe_config.parse_exports = False
pe_config.parse_resources = False
```

### 2. 内存管理

```python
def safe_analysis(file_path):
    """安全的分析函数"""
    try:
        binary = lief.parse(file_path)
        if binary is None:
            return None
        
        # 执行分析
        result = perform_analysis(binary)
        
        # 清理
        del binary
        return result
        
    except Exception as e:
        return {"error": str(e)}
```

---

*此文档补充了 ELF 和 PE 格式的详细分析方法，为开发完整的二进制分析工具提供参考。*
