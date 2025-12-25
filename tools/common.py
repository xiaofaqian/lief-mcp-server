"""
Shared helpers for Mach-O MCP tools.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

import lief


def error_result(message: str, suggestion: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"error": message}
    if suggestion:
        payload["suggestion"] = suggestion
    payload.update(extra)
    return payload


def validate_file_path(file_path: str, require_write: bool = False) -> Optional[Dict[str, Any]]:
    if not os.path.exists(file_path):
        return error_result(
            f"文件不存在: {file_path}",
            "请检查文件路径是否正确，确保使用完整的绝对路径",
        )
    if not os.access(file_path, os.R_OK):
        return error_result(
            f"无权限读取文件: {file_path}",
            "请检查文件权限，确保当前用户有读取权限",
        )
    if require_write and not os.access(file_path, os.W_OK):
        return error_result(
            f"无权限写入文件: {file_path}",
            "请检查文件权限，确保当前用户有写入权限",
        )
    return None


def parse_macho(file_path: str) -> Tuple[Optional[lief.MachO.FatBinary], Optional[Dict[str, Any]]]:
    try:
        fat_binary = lief.MachO.parse(file_path)
    except Exception as exc:
        return None, error_result(
            f"解析 Mach-O 文件时发生错误: {str(exc)}",
            "文件可能已损坏或格式不支持",
            file_path=file_path,
        )
    if fat_binary is None:
        return None, error_result(
            "无法解析文件，可能不是有效的 Mach-O 文件",
            "请确认文件是有效的 Mach-O 格式文件",
            file_path=file_path,
        )
    return fat_binary, None


def format_size(size_bytes: int, precision: int = 2) -> str:
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.{precision}f} {units[unit_index]}"


def format_size_compact(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def format_version(version: Any, simple: bool = False) -> Any:
    if simple:
        try:
            if isinstance(version, list) and len(version) >= 3:
                return f"{version[0]}.{version[1]}.{version[2]}"
            if isinstance(version, int):
                major = (version >> 16) & 0xFFFF
                minor = (version >> 8) & 0xFF
                patch = version & 0xFF
                return f"{major}.{minor}.{patch}"
        except Exception:
            return str(version)
        return str(version)

    try:
        if isinstance(version, list) and len(version) >= 3:
            major, minor, patch = version[0], version[1], version[2]
            return {
                "raw": version,
                "formatted": f"{major}.{minor}.{patch}",
                "major": major,
                "minor": minor,
                "patch": patch,
            }
        if isinstance(version, int):
            major = (version >> 16) & 0xFFFF
            minor = (version >> 8) & 0xFF
            patch = version & 0xFF
            return {
                "raw": version,
                "formatted": f"{major}.{minor}.{patch}",
                "major": major,
                "minor": minor,
                "patch": patch,
            }
    except Exception as exc:
        return {
            "raw": version,
            "formatted": str(version),
            "error": f"版本号格式解析失败: {str(exc)}",
        }
    return {
        "raw": version,
        "formatted": str(version),
        "major": 0,
        "minor": 0,
        "patch": 0,
    }


def compile_regex_filter(pattern: Optional[str]) -> Tuple[Optional[Pattern[str]], Optional[Dict[str, Any]]]:
    if not pattern:
        return None, None
    try:
        return re.compile(pattern, re.IGNORECASE), None
    except re.error as exc:
        return None, error_result(
            f"正则表达式过滤器无效: {pattern}, 错误: {str(exc)}",
            "请检查正则表达式语法，例如：'^_.*' 或 '.*malloc.*'",
        )


def paginate_items(items: List[Any], offset: int, count: int) -> Tuple[List[Any], Dict[str, Any], Optional[Dict[str, Any]]]:
    total = len(items)
    if offset >= total and total > 0:
        return [], {}, error_result(
            f"偏移量 {offset} 超出范围，过滤后的总数为 {total}",
            f"请使用 0 到 {max(0, total - 1)} 之间的偏移量",
        )
    if count == 0:
        end_index = total
    else:
        end_index = min(offset + count, total)
    paged = items[offset:end_index]
    info = {
        "total": total,
        "requested_offset": offset,
        "requested_count": count,
        "returned_count": len(paged),
        "has_more": end_index < total,
        "next_offset": end_index if end_index < total else None,
        "end_index": end_index,
    }
    return paged, info, None


def detect_number_format(number_str: str) -> str:
    text = number_str.strip().lower()
    if text.startswith("-0x") or text.startswith("0x"):
        return "hex"
    if re.search(r"[a-f]", text):
        return "hex"
    return "dec"


def parse_number(
    value: str,
    format_hint: str = "auto",
    prefer_hex: bool = False,
) -> Tuple[Optional[int], Optional[str], Optional[Dict[str, Any]]]:
    text = value.strip()
    if not text:
        return None, None, error_result("数值不能为空")
    detected = detect_number_format(text)
    if format_hint != "auto":
        detected = format_hint
    elif prefer_hex and detected == "dec" and text.lstrip("+-").isdigit():
        detected = "hex"
    base = 16 if detected == "hex" else 10
    try:
        return int(text, base), detected, None
    except ValueError as exc:
        return None, detected, error_result(f"无效的数值格式: {text}, 错误: {str(exc)}")


def select_architecture_by_name(
    fat_binary: lief.MachO.FatBinary, architecture: str
) -> Optional[lief.MachO.Binary]:
    if not architecture:
        return fat_binary[0] if len(fat_binary) > 0 else None
    arch_lower = architecture.lower()
    for binary in fat_binary:
        cpu_type_str = str(binary.header.cpu_type).lower()
        if arch_lower in cpu_type_str or cpu_type_str in arch_lower:
            return binary
    return None


def select_architecture_by_index(
    fat_binary: lief.MachO.FatBinary, architecture_index: int
) -> Tuple[Optional[lief.MachO.Binary], Optional[Dict[str, Any]]]:
    if architecture_index >= len(fat_binary):
        return None, error_result(
            f"架构索引 {architecture_index} 超出范围，文件只有 {len(fat_binary)} 个架构",
            f"请使用 0 到 {len(fat_binary) - 1} 之间的架构索引",
        )
    binary = fat_binary.at(architecture_index)
    if binary is None:
        return None, error_result(f"无法获取架构 {architecture_index} 的二进制文件")
    return binary, None


def get_available_architectures(fat_binary: lief.MachO.FatBinary) -> List[str]:
    return [str(binary.header.cpu_type) for binary in fat_binary]


def is_executable_address(binary: lief.MachO.Binary, address: int) -> bool:
    for segment in binary.segments:
        if segment.virtual_address <= address < segment.virtual_address + segment.virtual_size:
            if hasattr(segment, "flags") and "EXECUTE" in str(segment.flags):
                return True
            if segment.name in ["__TEXT"]:
                return True
    return False


def normalize_library_name(library_path: str) -> str:
    if not library_path:
        return "unknown"
    if ".framework/" in library_path:
        parts = library_path.split(".framework/")
        if len(parts) >= 2:
            return parts[0].split("/")[-1]
    return library_path.split("/")[-1]


def create_backup_path(
    file_path: str,
    *,
    suffix: str = "backup",
    separator: str = ".",
    timestamp_sep: str = "_",
    include_uuid: bool = False,
    include_microseconds: bool = False,
    insert_before_ext: bool = False,
) -> str:
    fmt = "%Y%m%d_%H%M%S_%f" if include_microseconds else "%Y%m%d_%H%M%S"
    timestamp = datetime.now().strftime(fmt)
    unique = f"{timestamp_sep}{uuid.uuid4().hex[:8]}" if include_uuid else ""
    tag = f"{suffix}{timestamp_sep}{timestamp}{unique}"
    if insert_before_ext:
        base, ext = os.path.splitext(file_path)
        return f"{base}{separator}{tag}{ext}"
    return f"{file_path}{separator}{tag}"


def write_macho(fat_binary: lief.MachO.FatBinary, output_path: str) -> Optional[Dict[str, Any]]:
    try:
        fat_binary.write(output_path)
        return None
    except Exception:
        # Fallback to single-arch write if needed.
        if len(fat_binary) == 1:
            try:
                fat_binary[0].write(output_path)
                return None
            except Exception as exc:
                return error_result(f"写入修改后的文件失败: {str(exc)}")
        return error_result("写入修改后的文件失败")
