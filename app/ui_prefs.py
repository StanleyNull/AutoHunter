"""外观偏好：主题色 / 背景图。元数据进 system_settings.ui，图片落在数据目录。"""
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.db.session import DB_PATH

WALLPAPER_STEM = "ui-wallpaper"
MAX_WALLPAPER_BYTES = 3 * 1024 * 1024
_ALLOWED_SIGS = (
    (b"\xff\xd8\xff", ".jpg", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", ".png", "image/png"),
    (b"GIF87a", ".gif", "image/gif"),
    (b"GIF89a", ".gif", "image/gif"),
    (b"RIFF", ".webp", "image/webp"),
)

DEFAULT_UI = {
    "theme": "dark",
    "accentHue": 235,
    "wallpaperKind": "none",
    "wallpaperUrl": "",
    "wallpaperFit": "cover",
    "wallpaperDim": 0.72,
    "saved": False,
}


def data_dir() -> Path:
    return Path(DB_PATH).resolve().parent


def wallpaper_paths() -> list[Path]:
    root = data_dir()
    return [p for p in root.glob(f"{WALLPAPER_STEM}.*") if p.is_file()]


def current_wallpaper() -> Path | None:
    files = wallpaper_paths()
    return files[0] if files else None


def detect_image(data: bytes) -> tuple[str, str] | None:
    if not data or len(data) > MAX_WALLPAPER_BYTES:
        return None
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return ".webp", "image/webp"
    for sig, ext, mime in _ALLOWED_SIGS:
        if sig != b"RIFF" and data.startswith(sig):
            return ext, mime
    return None


def save_wallpaper_bytes(data: bytes) -> Path:
    detected = detect_image(data)
    if not detected:
        raise ValueError("只接受 JPEG / PNG / GIF / WebP，且不超过 3MB")
    ext, _mime = detected
    root = data_dir()
    root.mkdir(parents=True, exist_ok=True)
    for old in wallpaper_paths():
        try:
            old.unlink()
        except OSError:
            pass
    dest = root / f"{WALLPAPER_STEM}{ext}"
    dest.write_bytes(data)
    try:
        dest.chmod(0o600)
    except OSError:
        pass
    return dest


def delete_wallpaper() -> None:
    for old in wallpaper_paths():
        try:
            old.unlink()
        except OSError:
            pass


def _clamp_hue(value: Any) -> int:
    try:
        n = int(round(float(value)))
    except (TypeError, ValueError):
        return DEFAULT_UI["accentHue"]
    return max(0, min(360, n))


def _clamp_dim(value: Any) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return DEFAULT_UI["wallpaperDim"]
    return max(0.35, min(0.92, n))


def _safe_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    return raw[:2000]


def normalize_ui(raw: Any, *, saved: bool | None = None) -> dict[str, Any]:
    src = dict(raw or {}) if isinstance(raw, dict) else {}
    kind = str(src.get("wallpaperKind") or "none").strip().lower()
    if kind not in {"none", "url", "file"}:
        kind = "none"
    url = _safe_url(src.get("wallpaperUrl"))
    file_on_disk = current_wallpaper() is not None
    if kind == "file" and not file_on_disk:
        kind = "none"
    if kind == "url" and not url:
        kind = "none"
    if kind != "file":
        file_on_disk = file_on_disk and kind == "file"
    mark = DEFAULT_UI["saved"]
    if saved is not None:
        mark = bool(saved)
    elif "saved" in src:
        mark = bool(src.get("saved"))
    elif src:
        mark = True
    return {
        "theme": "light" if src.get("theme") == "light" else "dark",
        "accentHue": _clamp_hue(src.get("accentHue", src.get("accent_hue"))),
        "wallpaperKind": kind,
        "wallpaperUrl": url if kind == "url" else "",
        "wallpaperFit": "contain" if src.get("wallpaperFit") == "contain" else "cover",
        "wallpaperDim": _clamp_dim(src.get("wallpaperDim", src.get("wallpaper_dim"))),
        "saved": mark,
        "wallpaperSet": kind == "file" and current_wallpaper() is not None,
        "wallpaperVersion": int(current_wallpaper().stat().st_mtime) if current_wallpaper() else 0,
    }


def public_ui(raw: Any) -> dict[str, Any]:
    ui = normalize_ui(raw)
    if ui["wallpaperKind"] == "file":
        ui["wallpaperSrc"] = f"/api/settings/ui/wallpaper?v={ui['wallpaperVersion']}"
    elif ui["wallpaperKind"] == "url":
        ui["wallpaperSrc"] = ui["wallpaperUrl"]
    else:
        ui["wallpaperSrc"] = ""
    return ui
