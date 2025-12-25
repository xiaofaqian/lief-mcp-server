"""
ELF 动态条目（Dynamic Entries）信息获取工具
"""

from typing import Annotated, Dict, Any, List
from pydantic import Field
import lief

from .common import validate_file_path
from .elf_common import parse_elf


def get_elf_dynamic(
    file_path: Annotated[str, Field(
        description="ELF文件在系统中的完整绝对路径，例如：/system/lib64/libc.so 或 /data/local/tmp/test.so"
    )]
) -> Dict[str, Any]:
    """
    获取 ELF 文件中的 Dynamic Entries 详细信息。
    """
    try:
        path_error = validate_file_path(file_path)
        if path_error:
            return path_error

        elf, parse_error = parse_elf(file_path)
        if parse_error:
            return parse_error

        entries: List[Dict[str, Any]] = []
        for entry in elf.dynamic_entries:
            try:
                tag = str(entry.tag).split(".")[-1]
                info: Dict[str, Any] = {
                    "tag": tag,
                    "raw_tag": str(entry.tag),
                }
                if tag in ["NEEDED", "SONAME", "RPATH", "RUNPATH"]:
                    info["name"] = getattr(entry, "name", None)
                elif tag in ["INIT_ARRAY", "FINI_ARRAY", "PREINIT_ARRAY"] and isinstance(entry, lief.ELF.DynamicEntryArray):
                    info["array"] = [hex(addr) for addr in entry.array]
                else:
                    info["value"] = hex(entry.value) if hasattr(entry, "value") else None
                entries.append(info)
            except Exception as exc:
                entries.append({
                    "error": f"解析动态条目时发生错误: {str(exc)}"
                })

        return {
            "file_path": file_path,
            "format": "ELF",
            "dynamic_entries_count": len(entries),
            "dynamic_entries": entries,
        }

    except Exception as exc:
        return {
            "error": f"解析 ELF 动态条目时发生未预期的错误: {str(exc)}",
            "file_path": file_path,
            "suggestion": "请检查文件格式是否正确，或联系技术支持",
        }
