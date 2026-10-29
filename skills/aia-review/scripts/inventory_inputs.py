#!/usr/bin/env python3
"""Hash a selected engineering-document directory. No conversion or network use."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

EXTENSIONS = {'.pdf', '.dwg', '.dxf', '.ifc', '.rvt', '.xlsx', '.xls', '.csv',
              '.docx', '.doc', '.txt', '.md', '.png', '.jpg', '.jpeg', '.tif', '.tiff'}
IGNORED = {'.git', '.venv', 'node_modules', '__pycache__'}

def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def inside_root(path, root):
    """True only when the entry really lives under the authorized root.

    is_symlink() is not enough: a Windows junction or a mount point redirects
    elsewhere without being reported as a symlink, so the walk would hash files
    that the reviewer never authorized.
    """
    try:
        return path.resolve(strict=True).is_relative_to(root)
    except OSError:
        return False

def inventory(root, output=None):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Input root must be a directory')
    selected, skipped = [], []
    def visit(directory):
        for p in sorted(directory.iterdir(), key=lambda v: v.name):
            relative = p.relative_to(root).as_posix()
            if p.is_symlink():
                skipped.append({'path': relative, 'reason': 'symlink'})
            elif not inside_root(p, root):
                skipped.append({'path': relative, 'reason': 'outside_root'})
            elif p.name.startswith('.') or p.name in IGNORED:
                continue
            elif p.is_dir():
                visit(p)
            elif p.is_file() and p.suffix.lower() in EXTENSIONS:
                if output and p.resolve() == Path(output).resolve():
                    continue
                before = p.stat()
                sha = file_hash(p)
                after = p.stat()
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                    raise ValueError(f'File changed during hashing: {relative}')
                selected.append({'candidate_id': f'SRC-{len(selected)+1:04d}',
                                 'path': relative, 'bytes': after.st_size,
                                 'sha256': sha, 'extension': p.suffix.lower(),
                                 'mtime_utc': datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat(),
                                 'authority': 'unconfirmed', 'capability': 'unprobed'})
    visit(root)
    return {'schema_version': '1.0', 'root': str(root),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'note': 'Candidate inventory only; not an issued drawing baseline or parsing result.',
            'files': selected, 'skipped': skipped}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('root', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError('Output already exists; select a new filename to preserve the previous inventory')
        result = inventory(args.root, args.output)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'files': len(result['files']), 'skipped': len(result['skipped']),
                          'output': str(args.output.resolve())}, ensure_ascii=False))
    except (OSError, ValueError) as exc:
        ap.exit(2, f'Inventory failed: {exc}\n')

if __name__ == '__main__':
    main()
