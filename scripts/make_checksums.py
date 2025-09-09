import hashlib, os, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()

EXCLUDES = {
    ".git", ".gitignore", ".gitattributes",
    "checksums.txt", "scripts/make_checksums.py",
    "scripts/pack_release_zip.ps1", "scripts/pack_release_zip.sh",
}

def should_skip(path):
    rel = os.path.relpath(path, ROOT).replace("\\", "/")
    return any(part in rel for part in EXCLUDES)

def main():
    out_lines = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git",)]
        for fn in files:
            p = os.path.join(base, fn)
            if should_skip(p):
                continue
            rel = os.path.relpath(p, ROOT).replace("\\", "/")
            try:
                out_lines.append(f"{sha256_of(p)}  {rel}")
            except Exception as e:
                print(f"WARN: {rel}: {e}", file=sys.stderr)
    out_lines.sort(key=lambda s: s.split("  ", 1)[-1].lower())
    with open(os.path.join(ROOT, "checksums.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines) + "\n")
    print("checksums.txt written.")

if __name__ == "__main__":
    main()
