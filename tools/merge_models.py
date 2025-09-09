
"""
Models Merger Utility
- Merges your existing C:\TechGuyTool_Project\data\android_models.json
  with the provided data\master_catalog.json (superset).
- Result is written back to C:\TechGuyTool_Project\data\android_models.json
  with a union of brands/models and merged fields.

Run from a terminal:
  > python tools\merge_models.py
"""

import json, sys
from pathlib import Path

PROJECT_ROOT = Path(r"C:\TechGuyTool_Project")
TARGET = PROJECT_ROOT / "data" / "android_models.json"
MASTER = PROJECT_ROOT / "data" / "master_catalog.json"

def deep_merge(a, b):
    # dicts: merge by key
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            if k in out:
                out[k] = deep_merge(out[k], v)
            else:
                out[k] = v
        return out
    # lists: union preserving order
    if isinstance(a, list) and isinstance(b, list):
        seen = set()
        out = []
        for x in a + b:
            key = json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else x
            if key not in seen:
                seen.add(key)
                out.append(x)
        return out
    # scalars / mismatched types: prefer b (newer catalog)
    return b

def main():
    if not TARGET.exists():
        print(f"[!] Existing catalog not found: {TARGET}")
        print("    Create the file first (even an empty {} JSON) or copy your current one.")
        sys.exit(1)
    if not MASTER.exists():
        print(f"[!] Master catalog not found: {MASTER}")
        print("    Make sure you copied data\\master_catalog.json into the project.")
        sys.exit(1)

    with open(TARGET, "r", encoding="utf-8") as f:
        try:
            current = json.load(f)
        except Exception:
            print("[!] Could not parse current android_models.json; starting from empty {}.")
            current = {}

    with open(MASTER, "r", encoding="utf-8") as f:
        base = json.load(f)

    merged = deep_merge(current, base)
    with open(TARGET, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    print("[OK] Merged master_catalog.json into data\\android_models.json")

if __name__ == "__main__":
    main()
