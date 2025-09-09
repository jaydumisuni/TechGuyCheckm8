# gui/doctor.py (top section)

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Callable, List, Optional, Tuple, Dict
import json, os, platform, shutil, socket, time
from pathlib import Path

# ---------- Public schema (stable for HAUNTER) ----------

@dataclass
class DoctorItem:
    id: str                 # stable id for AI
    name: str               # human name
    severity: str           # "OK" | "WARN" | "FAIL"
    details: str = ""
    fix_id: Optional[str] = None

# Fix registry maps id -> callable
_FIX_REGISTRY: Dict[str, Callable[[], Tuple[bool, str]]] = {}

def _register_fix(fix_id: str):
    def wrap(fn: Callable[[], Tuple[bool, str]]):
        _FIX_REGISTRY[fix_id] = fn
        return fn
    return wrap

# ---------- Core checker (no-Qt) ----------
def run_doctor_checks(app_root: Path | None = None, resource_path: Callable[[str], str] | None = None,
                      prefs_module=None) -> List[DoctorItem]:
    """
    Headless engine. Returns a list of DoctorItem (JSON-serializable via asdict()).
    No Qt imports here so HAUNTER can call this safely.
    """
    items: List[DoctorItem] = []
    root = Path.cwd().resolve() if app_root is None else Path(app_root).resolve()

    # Derive defaults if not supplied
    if resource_path is None:
        def resource_path(rel: str) -> str:
            return str((root / rel).resolve())

    res_dir = Path(resource_path("resources")).resolve()
    cfg_dir = root / "config"
    logs_dir = root / "logs"
    tools_dir = Path("C:/TechGuyTools/bin") if platform.system() == "Windows" else (
        (Path.home() / "Downloads" / "TechGuyTools" / "bin") if platform.system() == "Darwin"
        else (Path.home() / ".techguy" / "bin")
    )

    # 0) Project folders
    missing_dirs = [p for p in [res_dir, cfg_dir, logs_dir, tools_dir] if not p.exists()]
    if missing_dirs:
        items.append(DoctorItem(
            id="dirs.present", name="Project folders",
            severity="WARN", details="Missing: " + ", ".join(str(d) for d in missing_dirs),
            fix_id="dirs.create"
        ))
    else:
        items.append(DoctorItem(id="dirs.present", name="Project folders", severity="OK", details="All present"))

    # 1) Resources present
    must = ["sun.png", "moon.png", "background.png", "background2.png", "my_logo.png"]
    missing = [m for m in must if not (res_dir / m).exists()]
    if missing:
        items.append(DoctorItem(
            id="resources.present", name="Resources present",
            severity="FAIL", details=f"Missing: {', '.join(missing)} in {res_dir}",
            fix_id="resources.placeholders"
        ))
    else:
        items.append(DoctorItem(id="resources.present", name="Resources present", severity="OK", details=str(res_dir)))

    # 2) Prefs read/write
    if prefs_module is None:
        items.append(DoctorItem(id="prefs.status", name="Preferences", severity="WARN", details="prefs unavailable"))
    else:
        try:
            d = prefs_module.load()
            d.setdefault("doctor_probe", True)
            prefs_module.save(d)
            items.append(DoctorItem(id="prefs.status", name="Preferences", severity="OK", details="Readable & writable"))
        except Exception as e:
            items.append(DoctorItem(id="prefs.status", name="Preferences", severity="FAIL", details=str(e), fix_id="prefs.reset"))

    # 3) Background images at least one
    if (res_dir / "background.png").exists() or (res_dir / "background2.png").exists():
        items.append(DoctorItem(id="backgrounds.present", name="Background images", severity="OK", details="At least one present"))
    else:
        items.append(DoctorItem(id="backgrounds.present", name="Background images", severity="WARN", details="None found"))

    # 4) Import smoke tests (lazy/optional)
    mod_errs = []
    try:
        from gui.apple_hub import AppleHub  # noqa
    except Exception as e:
        mod_errs.append(f"AppleHub import failed: {e}")
    try:
        from gui.android_hub import AndroidHub  # noqa
    except Exception as e:
        mod_errs.append(f"AndroidHub import failed: {e}")
    try:
        from qt_assets import set_app_branding, resource_path as _rp  # noqa
    except Exception as e:
        mod_errs.append(f"qt_assets import failed: {e}")
    if mod_errs:
        items.append(DoctorItem(id="modules.imports", name="Module imports", severity="FAIL", details="; ".join(mod_errs)))
    else:
        items.append(DoctorItem(id="modules.imports", name="Module imports", severity="OK", details="apple_hub, android_hub, qt_assets"))

    # 5) Android tools
    adb = shutil.which("adb")
    fastboot = shutil.which("fastboot")
    if adb and fastboot:
        items.append(DoctorItem(id="android.tools", name="Android tools", severity="OK", details=f"adb: {adb}, fastboot: {fastboot}"))
    else:
        gaps = []
        if not adb: gaps.append("adb")
        if not fastboot: gaps.append("fastboot")
        items.append(DoctorItem(id="android.tools", name="Android tools", severity="WARN", details="Missing: " + ", ".join(gaps), fix_id="android.note"))

    # 6) Apple tools
    idevice = shutil.which("ideviceinstaller") or shutil.which("idevice_id")
    items.append(DoctorItem(
        id="apple.tools", name="Apple tools",
        severity="OK" if idevice else "WARN",
        details=f"Found: {idevice}" if idevice else "libimobiledevice not found"
    ))

    # 7) Network
    ok_dns = _can_resolve("one.one.one.one")
    ok_tcp = _can_tcp("1.1.1.1", 53, timeout=1.0)
    net_status = "OK" if ok_dns and ok_tcp else ("WARN" if ok_dns or ok_tcp else "FAIL")
    items.append(DoctorItem(id="network.basic", name="Network", severity=net_status, details=f"DNS:{ok_dns} TCP53:{ok_tcp}"))

    # 8) Qt env overrides
    qt_env = [f"{k}={os.environ[k]}" for k in ("QT_OPENGL","QT_QUICK_BACKEND","QT_WIDGETS_RHI","QT_SCALE_FACTOR_ROUNDING_POLICY") if k in os.environ]
    items.append(DoctorItem(id="qt.env", name="Qt render env", severity="WARN" if qt_env else "OK", details="; ".join(qt_env) or "Default"))

    # 9) Disk space + write perms
    usage = shutil.disk_usage(root)
    writable = _can_write_here(root)
    items.append(DoctorItem(id="storage.basic", name="Storage", severity="OK" if usage.free > 512*1024**2 else "WARN",
                            details=f"free_bytes={usage.free}; writeable={writable}"))

    # 10) Runtime
    import sys
    try:
        from PyQt6 import QtCore
        qt_ver = QtCore.QT_VERSION_STR
        pyqt_ver = QtCore.PYQT_VERSION_STR
    except Exception:
        qt_ver = pyqt_ver = "unknown"
    items.append(DoctorItem(id="runtime.info", name="Runtime", severity="OK",
                            details=f"Python {sys.version.split()[0]} • PyQt {pyqt_ver} / Qt {qt_ver} • {platform.system()} {platform.release()}"))

    # 11) Future: HAUNTER config
    haunter_cfg = cfg_dir / "haunter.json"
    if not haunter_cfg.exists():
        items.append(DoctorItem(id="haunter.config", name="HAUNTER config", severity="WARN",
                                details="Missing config/haunter.json", fix_id="haunter.stub"))
    else:
        try:
            data = json.loads(haunter_cfg.read_text(encoding="utf-8"))
            ok = isinstance(data, dict) and "name" in data and "features" in data
            items.append(DoctorItem(id="haunter.config", name="HAUNTER config", severity="OK" if ok else "WARN",
                                    details="Valid" if ok else "Unexpected structure"))
        except Exception as e:
            items.append(DoctorItem(id="haunter.config", name="HAUNTER config", severity="FAIL", details=f"Unreadable: {e}"))

    return items

def write_report_json(items: List[DoctorItem], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(i) for i in items], f, indent=2)

def apply_fix_by_id(fix_id: str) -> Tuple[bool, str]:
    fn = _FIX_REGISTRY.get(fix_id)
    if not fn:
        return False, f"Unknown fix_id: {fix_id}"
    return fn()

# ---------- Fix implementations (no-Qt) ----------

@_register_fix("dirs.create")
def _fix_dirs_create():
    try:
        root = Path.cwd().resolve()
        res_dir = root / "resources"
        cfg_dir = root / "config"
        logs_dir = root / "logs"
        if platform.system() == "Windows":
            tools_dir = Path("C:/TechGuyTools/bin")
        elif platform.system() == "Darwin":
            tools_dir = Path.home() / "Downloads" / "TechGuyTools" / "bin"
        else:
            tools_dir = Path.home() / ".techguy" / "bin"
        for d in (res_dir, cfg_dir, logs_dir, tools_dir):
            d.mkdir(parents=True, exist_ok=True)
        return True, "Created project folders"
    except Exception as e:
        return False, str(e)

@_register_fix("resources.placeholders")
def _fix_resources_placeholders():
    try:
        res_dir = (Path.cwd() / "resources")
        res_dir.mkdir(parents=True, exist_ok=True)
        for name in ("sun.png","moon.png","background.png","background2.png","my_logo.png"):
            (res_dir / name).write_bytes(_png_placeholder_bytes(name))
        return True, "Placeholder images created"
    except Exception as e:
        return False, str(e)

@_register_fix("prefs.reset")
def _fix_prefs_reset():
    try:
        from utils import prefs as prefs_module  # lazy import
        prefs_module.save({"glass_theme": "dark"})
        return True, "Preferences reset to defaults"
    except Exception as e:
        return False, str(e)

@_register_fix("android.note")
def _fix_android_note():
    try:
        tools_dir = Path("C:/TechGuyTools/bin") if platform.system() == "Windows" else (
            (Path.home() / "Downloads" / "TechGuyTools" / "bin") if platform.system() == "Darwin"
            else (Path.home() / ".techguy" / "bin")
        )
        tools_dir.mkdir(parents=True, exist_ok=True)
        (tools_dir / "README_ANDROID_TOOLS.txt").write_text(
            "Place adb and fastboot binaries here or add them to PATH.\n", encoding="utf-8"
        )
        return True, f"Helper note written to {tools_dir}"
    except Exception as e:
        return False, str(e)

@_register_fix("haunter.stub")
def _fix_haunter_stub():
    try:
        cfg_dir = Path.cwd() / "config"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        stub = {
            "name": "HAUNTER",
            "enabled": False,
            "hotkey": "Ctrl+Shift+H",
            "wake_word": "haunter",
            "model": "local",
            "features": {"chat": True, "transcribe": False, "summarize": False}
        }
        (cfg_dir / "haunter.json").write_text(json.dumps(stub, indent=2), encoding="utf-8")
        return True, "Created config/haunter.json"
    except Exception as e:
        return False, str(e)

# ---------- small helpers ----------
def _can_write_here(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        t = path / ".doctor_touch"
        t.write_text("ok", encoding="utf-8"); t.unlink(missing_ok=True)
        return True
    except Exception:
        return False

def _can_resolve(host: str) -> bool:
    try:
        socket.gethostbyname(host); return True
    except Exception:
        return False

def _can_tcp(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        import socket
        with socket.create_connection((host, port), timeout=timeout): return True
    except Exception:
        return False
