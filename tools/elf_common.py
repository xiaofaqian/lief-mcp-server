"""
ELF/Android shared helpers for MCP tools.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import lief

from .common import error_result


def parse_elf(file_path: str) -> Tuple[Optional[lief.ELF.Binary], Optional[Dict[str, Any]]]:
    try:
        elf = lief.ELF.parse(file_path)
    except Exception as exc:
        return None, error_result(
            f"解析 ELF 文件时发生错误: {str(exc)}",
            "文件可能已损坏或格式不支持",
            file_path=file_path,
        )
    if elf is None:
        return None, error_result(
            "无法解析文件，可能不是有效的 ELF 文件",
            "请确认文件是有效的 ELF 格式文件",
            file_path=file_path,
        )
    return elf, None


def get_build_id(elf: lief.ELF.Binary) -> Optional[str]:
    if not getattr(elf, "has_notes", False):
        return None
    for note in elf.notes:
        try:
            if str(note.type).endswith("GNU_BUILD_ID"):
                desc = getattr(note, "description", None)
                if desc is None:
                    return None
                return bytes(desc).hex()
        except Exception:
            continue
    return None


def get_android_ident(elf: lief.ELF.Binary) -> Optional[Dict[str, Any]]:
    if not getattr(elf, "has_notes", False):
        return None
    for note in elf.notes:
        if getattr(note, "name", "") != "Android":
            continue
        info: Dict[str, Any] = {"name": "Android"}
        if hasattr(note, "sdk_version"):
            info["sdk_version"] = note.sdk_version
        if hasattr(note, "ndk_version"):
            info["ndk_version"] = note.ndk_version
        return info
    return None


def parse_segment_flags(flags: Any) -> List[str]:
    flags_text = str(flags)
    parsed: List[str] = []
    if "R" in flags_text:
        parsed.append("READ")
    if "W" in flags_text:
        parsed.append("WRITE")
    if "X" in flags_text:
        parsed.append("EXECUTE")
    return parsed if parsed else ["NONE"]


def parse_section_flags(section: lief.ELF.Section) -> List[str]:
    try:
        return [str(flag) for flag in section.flags_list]
    except Exception:
        return []


def is_executable_address(elf: lief.ELF.Binary, address: int) -> bool:
    for segment in elf.segments:
        try:
            if segment.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            if segment.virtual_address <= address < segment.virtual_address + segment.virtual_size:
                if "X" in str(segment.flags):
                    return True
        except Exception:
            continue
    return False
