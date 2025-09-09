#!/usr/bin/env python3
import argparse, json, shutil, datetime, os
from pathlib import Path

def load_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default

def dump_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

def merge_brands(base, ext):
    merged = dict(base)
    for brand, series in ext.items():
        base_set = set(merged.get(brand, []))
        merged[brand] = sorted(base_set.union(series))
    return merged

def merge_models(base, ext):
    seen = {(m["brand"], m["model"]) for m in base}
    merged = list(base)
    added = 0
    for m in ext:
        key = (m.get("brand"), m.get("model"))
        if key not in seen:
            merged.append(m)
            seen.add(key)
            added += 1
    return merged, added

def main():
    ap = argparse.ArgumentParser(description="TechGuy Tool DB Patch Merger (safe by default)")
    ap.add_argument("--project-root", required=True, help="Path to your TechGuy Tool project root")
    ap.add_argument("--in-place", action="store_true", help="Overwrite brands.json/models.json after backup")
    args = ap.parse_args()

    root = Path(args.project_root)
    data_dir = root / "data"
    ext_dir = Path(__file__).resolve().parent.parent / "data"

    # Paths
    base_brands = data_dir / "brands.json"
    base_models = data_dir / "models.json"
    ext_brands = ext_dir / "brands_extended.json"
    ext_models = ext_dir / "models_extended.json"

    # Load
    brands_base = load_json(base_brands, {})
    models_base = load_json(base_models, [])
    brands_ext = load_json(ext_brands, {})
    models_ext = load_json(ext_models, [])

    # Merge
    brands_merged = merge_brands(brands_base, brands_ext)
    models_merged, added = merge_models(models_base, models_ext)

    # Backup
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = data_dir / f"backup_{ts}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    if base_brands.exists(): shutil.copy2(base_brands, backup_dir / "brands.json")
    if base_models.exists(): shutil.copy2(base_models, backup_dir / "models.json")

    if args.in_place:
        dump_json(base_brands, brands_merged)
        dump_json(base_models, models_merged)
        out_brands = base_brands
        out_models = base_models
    else:
        out_brands = data_dir / "brands_merged.json"
        out_models = data_dir / "models_merged.json"
        dump_json(out_brands, brands_merged)
        dump_json(out_models, models_merged)

    print("Patch applied safely.")
    print(f"Backup folder: {backup_dir}")
    print(f"Brands written to: {out_brands}")
    print(f"Models written to: {out_models}")
    print(f"Models added: {added} (dedup by (brand, model))")

if __name__ == "__main__":
    main()
