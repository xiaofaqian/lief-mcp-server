# Android ELF 工具体系开发文档（基于 LIEF 0.17.0.post2686）

## 1. 版本与资料来源

- 本项目当前使用的 LIEF 版本（来自本目录 wheel）：`lief_extended-0.17.0.post2686-cp313-cp313-macosx_11_0_arm64.whl`
- 官方最新 release（官网仓库 releases）：`0.17.1`
- 官方文档来源：通过 Context7 读取 LIEF 官方仓库文档（`doc/sphinx/formats/elf/index.rst`、`doc/sphinx/_cross_api.rst`、`doc/sphinx/changelog.rst` 等）。

> 说明：本地 wheel 版本与官方最新 release 存在细微差异（post 版 vs release 版）。实现时以本地 wheel 行为为准，但接口设计优先对齐官方文档。

## 2. 目标与范围

目标是在 Android/ELF 场景下提供与现有 Mach-O 工具一致的功能集合，包括解析、枚举、统计、查询、以及有限的二进制修改能力。范围包括：

- ELF32/ELF64
- ARMv7 / ARM64 / x86_64（按实际二进制自动识别）
- 重点覆盖 `.so` 动态库与 ELF 可执行文件

## 3. 总体架构

- 复用 `tools/common.py`：文件校验、正则过滤、分页、数字解析、格式化、备份、写入等通用逻辑。
- 新增 `tools/elf_common.py`（建议）：ELF 特有的解析/定位/标签/地址映射工具。
- 工具命名建议：`list_elf_* / get_elf_* / parse_elf_*`，保持与 Mach-O 工具一致的接口风格与输出结构。

## 4. 功能映射表（Mach-O → ELF）

| Mach-O 工具 | Android ELF 对应工具 | 说明 |
|---|---|---|
| `parse_macho_info` | `parse_elf_info` | ELF 头、架构、入口点、段/节/符号统计、BuildID、动态段概览 |
| `get_macho_header` | `get_elf_header` | ELF Header 字段完整输出 |
| `list_macho_segments` | `list_elf_segments` | Program Headers（PT_LOAD/FLAGS/VA/FILE/MEM） |
| `list_macho_sections` | `list_elf_sections` | Section Headers（TYPE/FLAGS/OFFSET/SIZE/ALIGN） |
| `list_macho_symbols` | `list_elf_symbols` | `.symtab` + `.dynsym`（类型/绑定/可见性） |
| `list_macho_imports` | `list_elf_imports` | 未定义动态符号 + 关联重定位（近似库关联） |
| `list_macho_exports` | `list_elf_exports` | 已定义全局符号 |
| `list_macho_libraries` | `list_elf_libraries` | `DT_NEEDED`/`RPATH`/`RUNPATH`/`SONAME` |
| `get_macho_load_commands` | `get_elf_dynamic` | Dynamic Entries 视图（等价“加载命令”） |
| `list_macho_relocations` | `list_elf_relocations` | `.rel/.rela/.plt` 重定位 |
| `disassemble_macho_code` | `disassemble_elf_code` | 建议 Capstone；LIEF ELF 反汇编需验证 |
| `assemble_macho_code` | `assemble_elf_code` | 建议 Keystone + 写回 |
| `add_macho_section` | `add_elf_section` | 新增节/段，注意对齐与扩展 |
| `add_macho_library` | `add_elf_library` | 新增 `DT_NEEDED` |
| `remove_macho_library` | `remove_elf_library` | 移除 `DT_NEEDED` |
| `find_got_symbol_by_address` | `find_elf_got_symbol_by_address` | `.got/.got.plt` + relocation 关联 |
| `replace_macho_symbol` | `replace_elf_symbol` | GOT/PLT 级替换（Hook） |

## 5. LIEF 官方文档要点（Context7 摘录）

### 5.1 解析与写入

```python
import lief

elf: lief.ELF.Binary = lief.ELF.parse("/bin/ls")
elf.write("new.elf")
```

- `lief.ELF.parse()` 解析 ELF
- `lief.ELF.Binary.write()` 写回文件
- `lief.ELF.Binary.write_to_bytes()` 可写入内存字节序列

### 5.2 动态条目（Dynamic Entries）

```python
for entry in binary.dynamic_entries:
    tag = str(entry.tag).split('.')[-1]
    if tag in ['NEEDED', 'SONAME', 'RPATH', 'RUNPATH']:
        print(tag, entry.name)
```

- ELF 的“加载命令”等价物就是 Dynamic Entries（`DT_*`）

### 5.3 增加 Section

```python
new_section = lief.ELF.Section()
new_section.name = ".mydata"
new_section.type = lief.ELF.Section.TYPE.PROGBITS
new_section.content = [0x41, 0x42, 0x43, 0x44] * 256
new_section = binary.add(new_section)
```

### 5.4 增加依赖库

```python
elf.add_library("libdemo.so")
elf.write("new.elf")
```

### 5.5 高级解析配置

```python
parser_config = lief.ELF.ParserConfig()
parser_config.parse_overlay = False

elf: lief.ELF.Binary = lief.ELF.parse("my.elf", parser_config)

builder_config = lief.ELF.Builder.config_t()
builder_config.gnu_hash = False
elf.write("new.elf", builder_config)
```

## 6. 输出结构约定（建议）

为保持与 Mach-O 工具一致性，建议 ELF 工具输出统一结构：

```json
{
  "file_path": "...",
  "format": "ELF",
  "architecture": "AARCH64",
  "is_multi_arch": false,
  "summary": { ... },
  "items": [ ... ],
  "pagination_info": { ... }
}
```

错误结构统一：

```json
{ "error": "...", "suggestion": "..." }
```

## 7. 关键工具实现要点

### 7.1 `parse_elf_info`
- ELF Header + Program/Section 统计
- BuildID/Notes（如果存在）
- Dynamic Entries 简要概览

### 7.2 `list_elf_segments` / `list_elf_sections`
- Segment 以 Program Headers 为主
- Section 包含 `.symtab/.dynsym/.rel/.rela/.plt/.got` 等重点节统计

### 7.3 `list_elf_symbols`
- 合并 `.symtab` 与 `.dynsym`
- 输出 binding/type/visibility/value/size

### 7.4 `list_elf_imports`
- 未定义动态符号（`st_shndx == UNDEF`）
- 结合 relocation 获取地址与用途

### 7.5 `list_elf_exports`
- 已定义的全局符号（`BIND=GLOBAL`）

### 7.6 `list_elf_libraries`
- `DT_NEEDED` / `DT_SONAME` / `DT_RPATH` / `DT_RUNPATH`

### 7.7 `get_elf_dynamic`
- 输出所有 Dynamic Entries
- 对 `DynamicEntryArray` 展开数组

### 7.8 `list_elf_relocations`
- `.rel/.rela/.plt` 全量重定位
- 输出：地址、类型、符号、addend、用途

### 7.9 `disassemble_elf_code` / `assemble_elf_code`
- 建议使用 Capstone/Keystone 完成
- LIEF 对 ELF 反汇编支持需单独验证

### 7.10 `add_elf_section`
- 注意对齐与段扩展
- 修改后可能需重新生成 hash / relocs

### 7.11 `add/remove_elf_library`
- 基于 `DT_NEEDED` 操作
- 修改后建议重新生成 hash 表

### 7.12 `replace_elf_symbol`
- 典型实现：定位 GOT/PLT 重定位并替换 symbol

## 8. Android ELF 额外注意点

- PIE 默认启用，入口点与 RVA 计算要正确转换
- RELRO/GNU_RELRO 会影响可写段修改
- `.so` 常被 strip，符号表可能缺失
- 对 `DT_ANDROID_REL` 等特殊条目要兼容

## 9. 测试策略

- 所有修改操作一律基于复制件（如 `/tmp/elf-test/xxx.so`）
- 读工具：基础覆盖 + 关键节（`.dynsym/.dynstr/.rela.*`）
- 写工具：新增库、移除库、增加节、写回验证

## 10. 与 Mach-O 工具一致性策略

- 命名与参数尽量与 Mach-O 工具一致
- 输出结构保持统一
- 错误处理与建议文本保持统一风格

## 11. 版本差异与风险提示

- 本地版本：`0.17.0.post2686`（wheel）
- 官方最新 release：`0.17.1`
- 建议：ELF 写入类操作必须在样本集上验证行为差异

## 12. 里程碑建议

1) 只读类工具完整对齐
2) 写入类工具（add/remove lib, add section）
3) Hook/替换符号工具与 GOT/PLT 路径完善

---

如需我直接开始生成 ELF 工具代码，请确认：
- 工具命名规范（`list_elf_*` 或 `android_*`）
- 是否加入 Capstone/Keystone 作为依赖
- 写入类操作是否默认仅在复制件上执行
