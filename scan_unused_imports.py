#!/usr/bin/env python3
"""
Mach-O 未使用导入符号扫描工具

此工具分析 Mach-O 文件，识别哪些导入符号实际上没有被代码使用。
使用多种检测方法来提高准确性。
"""

import lief
import re
import json
from typing import Set, List, Dict, Optional
from pathlib import Path


class UnusedImportScanner:
    """未使用导入符号扫描器"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.binary = None
        self.all_imports = set()
        self.referenced_symbols = set()
        
    def load_binary(self) -> bool:
        """加载二进制文件"""
        try:
            print(f"正在解析文件: {self.file_path}")
            
            # 检查文件是否存在
            if not Path(self.file_path).exists():
                print(f"错误: 文件不存在 - {self.file_path}")
                return False
            
            # 解析 Mach-O 文件
            fat_binary = lief.MachO.parse(self.file_path)
            if not fat_binary:
                print("错误: 无法解析 Mach-O 文件")
                return False
            
            # 获取第一个架构（通常是主架构）
            if len(fat_binary) == 0:
                print("错误: 文件中没有找到 Mach-O 架构")
                return False
                
            self.binary = fat_binary.at(0)
            print(f"成功加载架构: {self.binary.header.cpu_type}")
            return True
            
        except Exception as e:
            print(f"加载文件时出错: {e}")
            return False
    
    def get_all_import_symbols(self) -> Set[str]:
        """获取所有导入符号"""
        imports = set()
        
        try:
            # 方法1: 从导入符号列表获取
            for symbol in self.binary.imported_symbols:
                if symbol.name:
                    imports.add(symbol.name)
            
            # 方法2: 从绑定信息获取
            if hasattr(self.binary, 'dyld_info') and self.binary.dyld_info:
                for binding in self.binary.dyld_info.bindings:
                    if hasattr(binding, 'symbol') and binding.symbol and binding.symbol.name:
                        imports.add(binding.symbol.name)
            
            # 方法3: 从符号表获取未定义符号
            for symbol in self.binary.symbols:
                if (hasattr(symbol, 'type') and 
                    str(symbol.type) == "SYMBOL_TYPES.UNDEFINED" and 
                    symbol.name):
                    imports.add(symbol.name)
            
            print(f"找到 {len(imports)} 个导入符号")
            return imports
            
        except Exception as e:
            print(f"获取导入符号时出错: {e}")
            return set()
    
    def analyze_static_references(self) -> Set[str]:
        """通过静态分析检测被引用的符号"""
        referenced = set()
        
        try:
            print("正在进行静态代码分析...")
            
            # 获取代码段
            text_sections = []
            for segment in self.binary.segments:
                for section in segment.sections:
                    # 查找可执行的代码段
                    if (section.name == "__text" or 
                        "SOME_INSTRUCTIONS" in str(section.flags) or
                        "PURE_INSTRUCTIONS" in str(section.flags)):
                        text_sections.append(section)
            
            print(f"找到 {len(text_sections)} 个代码段")
            
            # 反汇编并分析调用
            instruction_count = 0
            for section in text_sections:
                try:
                    # 反汇编这个段
                    for instruction in self.binary.disassemble(section.virtual_address, section.size):
                        instruction_count += 1
                        
                        # 分析不同类型的调用指令
                        mnemonic = instruction.mnemonic.lower()
                        
                        # ARM64 调用指令
                        if mnemonic in ['bl', 'blr', 'b']:
                            target = self._extract_call_target(instruction)
                            if target and target in self.all_imports:
                                referenced.add(target)
                        
                        # x86_64 调用指令
                        elif mnemonic in ['call', 'jmp']:
                            target = self._extract_call_target(instruction)
                            if target and target in self.all_imports:
                                referenced.add(target)
                        
                        # 间接调用通过寄存器
                        elif 'call' in mnemonic or 'jmp' in mnemonic:
                            # 分析操作数中的符号引用
                            operands_str = str(instruction.operands)
                            for symbol_name in self.all_imports:
                                if symbol_name in operands_str:
                                    referenced.add(symbol_name)
                        
                        # 限制指令数量以避免过长时间
                        if instruction_count > 100000:  # 限制分析的指令数量
                            print("达到指令分析限制，停止反汇编")
                            break
                    
                    if instruction_count > 100000:
                        break
                        
                except Exception as e:
                    print(f"反汇编段 {section.name} 时出错: {e}")
                    continue
            
            print(f"分析了 {instruction_count} 条指令，找到 {len(referenced)} 个被引用的符号")
            return referenced
            
        except Exception as e:
            print(f"静态分析时出错: {e}")
            return set()
    
    def _extract_call_target(self, instruction) -> Optional[str]:
        """从指令中提取调用目标"""
        try:
            # 尝试从操作数中提取符号名
            operands_str = str(instruction.operands)
            
            # 查找符号名模式
            for symbol_name in self.all_imports:
                if symbol_name in operands_str:
                    return symbol_name
            
            return None
            
        except Exception:
            return None
    
    def analyze_pointer_table_usage(self) -> Set[str]:
        """分析符号指针表的使用情况"""
        referenced = set()
        
        try:
            print("正在分析符号指针表...")
            
            # 获取符号指针段
            pointer_sections = []
            for segment in self.binary.segments:
                for section in segment.sections:
                    if section.name in ["__la_symbol_ptr", "__nl_symbol_ptr", "__got"]:
                        pointer_sections.append(section)
            
            print(f"找到 {len(pointer_sections)} 个指针表段")
            
            # 分析指针表的使用
            # 这里简化处理，实际应该分析对这些地址的访问
            for section in pointer_sections:
                try:
                    # 通过重定位信息分析
                    for relocation in self.binary.relocations:
                        if (hasattr(relocation, 'address') and 
                            section.virtual_address <= relocation.address < 
                            section.virtual_address + section.size):
                            if hasattr(relocation, 'symbol') and relocation.symbol:
                                referenced.add(relocation.symbol.name)
                except Exception as e:
                    print(f"分析指针表段 {section.name} 时出错: {e}")
            
            print(f"从指针表分析中找到 {len(referenced)} 个被引用的符号")
            return referenced
            
        except Exception as e:
            print(f"指针表分析时出错: {e}")
            return set()
    
    def analyze_relocations(self) -> Set[str]:
        """分析重定位信息"""
        referenced = set()
        
        try:
            print("正在分析重定位信息...")
            
            # 分析重定位表
            for relocation in self.binary.relocations:
                try:
                    if hasattr(relocation, 'symbol') and relocation.symbol and relocation.symbol.name:
                        symbol_name = relocation.symbol.name
                        if symbol_name in self.all_imports:
                            referenced.add(symbol_name)
                except Exception as e:
                    continue
            
            # 分析绑定信息
            if hasattr(self.binary, 'dyld_info') and self.binary.dyld_info:
                for binding in self.binary.dyld_info.bindings:
                    try:
                        if hasattr(binding, 'symbol') and binding.symbol and binding.symbol.name:
                            symbol_name = binding.symbol.name
                            if symbol_name in self.all_imports:
                                referenced.add(symbol_name)
                    except Exception as e:
                        continue
            
            print(f"从重定位分析中找到 {len(referenced)} 个被引用的符号")
            return referenced
            
        except Exception as e:
            print(f"重定位分析时出错: {e}")
            return set()
    
    def scan(self) -> Dict:
        """执行完整扫描"""
        if not self.load_binary():
            return {"error": "无法加载二进制文件"}
        
        # 获取所有导入符号
        self.all_imports = self.get_all_import_symbols()
        if not self.all_imports:
            return {"error": "没有找到导入符号"}
        
        # 执行各种分析
        static_refs = self.analyze_static_references()
        pointer_refs = self.analyze_pointer_table_usage()
        reloc_refs = self.analyze_relocations()
        
        # 合并所有引用
        all_referenced = static_refs | pointer_refs | reloc_refs
        
        # 计算未使用的符号
        unused_symbols = self.all_imports - all_referenced
        
        # 生成报告
        result = {
            "file_path": self.file_path,
            "total_imports": len(self.all_imports),
            "referenced_symbols": len(all_referenced),
            "unused_symbols": len(unused_symbols),
            "analysis_methods": {
                "static_analysis": len(static_refs),
                "pointer_table_analysis": len(pointer_refs),
                "relocation_analysis": len(reloc_refs)
            },
            "all_imports": sorted(list(self.all_imports)),
            "referenced": sorted(list(all_referenced)),
            "unused": sorted(list(unused_symbols))
        }
        
        return result


def main():
    """主函数"""
    file_path = "/Users/mmd/WorkSpace/token/tp/project/Payload/Global Wallet.app/Global Wallet"
    
    print("=" * 60)
    print("Mach-O 未使用导入符号扫描工具")
    print("=" * 60)
    
    scanner = UnusedImportScanner(file_path)
    result = scanner.scan()
    
    if "error" in result:
        print(f"扫描失败: {result['error']}")
        return
    
    # 输出结果
    print("\n" + "=" * 60)
    print("扫描结果")
    print("=" * 60)
    
    print(f"文件路径: {result['file_path']}")
    print(f"总导入符号数: {result['total_imports']}")
    print(f"被引用符号数: {result['referenced_symbols']}")
    print(f"未使用符号数: {result['unused_symbols']}")
    
    print(f"\n分析方法统计:")
    for method, count in result['analysis_methods'].items():
        print(f"  {method}: {count} 个符号")
    
    if result['unused']:
        print(f"\n未使用的导入符号 ({len(result['unused'])} 个):")
        for i, symbol in enumerate(result['unused'], 1):
            print(f"  {i:3d}. {symbol}")
    else:
        print("\n所有导入符号都被使用")
    
    # 保存详细结果到 JSON 文件
    output_file = "unused_imports_report.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n详细报告已保存到: {output_file}")
    except Exception as e:
        print(f"保存报告时出错: {e}")
    
    print("\n" + "=" * 60)
    print("扫描完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
