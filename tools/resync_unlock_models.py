from pathlib import Path
import shutil

def main():
    proj = Path(r"C:\TechGuyTool_Project")
    src = proj / "data" / "android_models.json"
    cache = proj / "data" / "unlock_models_cache.json"
    if not src.exists():
        print("[!] data\android_models.json not found.")
        return
    try:
        shutil.copyfile(src, cache)
        print("[OK] Resynced unlock_models_cache.json from android_models.json")
    except Exception as e:
        print(f"[!] Copy failed: {e}")

if __name__ == "__main__":
    main()
