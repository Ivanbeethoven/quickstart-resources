"""Build (ingest) pipeline for repo -> RAG knowledge base.

NEW DIRECTORY LAYOUT (separates original repo and derived data):
    {root_dir}/{repo_name}/
        repo/              # original git clone (NOT copied elsewhere)
        data/
            issues/          # issue_*.md
            prs/             # pr_*.md
            security/        # sec_*.md
            chunks/          # optional raw chunk text files (if --save-chunks)
        rag_embeddings/    # index.faiss, index.pkl, meta.jsonl, config.json

Legacy layout (code/, issue/, pr/, security/) is deprecated. If detected, a warning is printed.

CLI example:
    python -m opensource_rag.build --repo-url https://github.com/cubefs/cubefs --root-dir ./kb \
            --max-files 1200 --save-chunks

Environment:
    GH_TOKEN / GITHUB_TOKEN  (optional) for higher GitHub API rate limits.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import shutil
import time
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from git import Repo, GitCommandError  # type: ignore
from rich import print
from tqdm import tqdm

from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.schema import Document

TEXT_EXT = {
    ".py", ".md", ".txt", ".rst", ".cfg", ".ini", ".toml", ".json",
    ".yml", ".yaml", ".java", ".js", ".ts", ".tsx", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".go", ".rs", ".sh", ".bash", ".zsh", ".ps1",
    ".sql", ".pl", ".rb", ".php", ".scala", ".kt", ".swift"
}
CODE_EXT = {
    ".py", ".java", ".js", ".ts", ".tsx", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".go", ".rs", ".rb", ".php", ".scala", ".kt", ".swift"
}
IGNORE_DIR = {".git", ".github", "__pycache__", "node_modules", "dist", "build", ".venv", "venv", ".idea", ".vscode"}

# ---------- basic utils ----------

def _normalize_repo_name(repo_url: str) -> str:
    name = repo_url.rstrip('/').split('/')[-1]
    if name.endswith('.git'):
        name = name[:-4]
    return name


def clone_or_update(repo_url: str, clone_dir: Path) -> Path:
    if (clone_dir / '.git').exists():
        try:
            print(f"[cyan]Repo exists, pulling: {clone_dir}")
            Repo(clone_dir).remote().pull()
        except GitCommandError as e:  # pragma: no cover
            print(f"[red]Pull failed: {e}")
    else:
        if clone_dir.exists() and any(clone_dir.iterdir()):
            # ensure empty dir for fresh clone
            shutil.rmtree(clone_dir)
        print(f"[green]Cloning {repo_url} -> {clone_dir}")
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        Repo.clone_from(repo_url, clone_dir)
    return clone_dir

def is_text_file(p: Path, max_bytes: int = 2_000_000) -> bool:
    try:
        if p.stat().st_size > max_bytes:
            return False
    except FileNotFoundError:
        return False
    try:
        with p.open('rb') as f:
            if b'\0' in f.read(2048):
                return False
    except Exception:
        return False
    if p.suffix.lower() in TEXT_EXT:
        return True
    mt, _ = mimetypes.guess_type(str(p))
    return bool(mt and ("text" in mt or "json" in mt))

def read_file(p: Path) -> str:
    try:
        return p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''

def md5(s: str) -> str:
    import hashlib
    return hashlib.md5(s.encode('utf-8', errors='ignore')).hexdigest()

def collect_files(repo_path: Path, max_files: int | None) -> List[Path]:
    out: List[Path] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIR]
        for fn in files:
            p = Path(root) / fn
            if is_text_file(p):
                out.append(p)
    out.sort()
    if max_files:
        out = out[:max_files]
    return out

# ---------- chunking ----------

def split_code(text: str, max_lines: int = 160, overlap: int = 20) -> List[str]:
    lines = text.splitlines()
    chunks: List[str] = []
    buf: List[str] = []
    pat = re.compile(r'^\s*(def |class |//|/\*|function |#[^!])')
    def flush():
        if buf:
            chunks.append('\n'.join(buf).strip())
    for line in lines:
        if (len(buf) >= max_lines) or (pat.match(line) and len(buf) >= 40):
            flush()
            if overlap and len(buf) > overlap:
                buf[:] = buf[-overlap:]
            else:
                buf = []  # type: ignore
        buf.append(line)
    flush()
    return [c for c in chunks if c.strip()]

def split_text(text: str, max_chars: int = 1600, overlap: int = 200) -> List[str]:
    paras = re.split(r'\n{2,}', text)
    chunks: List[str] = []
    buf = ''
    for p in paras:
        p = p.strip()
        if not p:
            continue
        if len(p) > max_chars:
            for i in range(0, len(p), max_chars - overlap):
                chunks.append(p[i:i+max_chars])
            continue
        if len(buf) + len(p) + 2 <= max_chars:
            buf = buf + ('\n\n' if buf else '') + p
        else:
            if buf:
                chunks.append(buf)
            buf = p
    if buf:
        chunks.append(buf)
    if overlap and overlap < max_chars:
        merged, tail = [], ''
        for c in chunks:
            merged.append((tail + c) if tail else c)
            tail = c[-overlap:]
        chunks = merged
    return chunks

def chunk_file(p: Path) -> List[Dict]:
    text = read_file(p)
    if not text.strip():
        return []
    ext = p.suffix.lower()
    raw = split_code(text) if ext in CODE_EXT else split_text(text)
    tp = 'code' if ext in CODE_EXT else 'text'
    base_hash = md5(str(p))
    out = []
    for i, c in enumerate(raw):
        if not c.strip():
            continue
        out.append({
            'file': str(p),
            'chunk_id': f'{base_hash}_{i}',
            'content': c,
            'type': tp,
            'size': len(c),
            'lines': c.count('\n') + 1,
            'source': 'repo'
        })
    return out

# ---------- github meta ----------

def parse_owner_repo(url: str) -> Tuple[str, str] | None:
    m = re.match(r'https?://github.com/([^/]+)/([^/]+?)(?:\.git)?$', url.strip())
    return (m.group(1), m.group(2)) if m else None

def gh_headers() -> Dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    token = os.getenv('GH_TOKEN') or os.getenv('GITHUB_TOKEN')
    if token:
        h['Authorization'] = f'Bearer {token}'
    return h

def fetch_paginated(url: str, limit: int) -> List[Dict]:
    items: List[Dict] = []
    page = 1
    while len(items) < limit:
        r = requests.get(url, headers=gh_headers(), params={'per_page': 100, 'page': page}, timeout=30)
        if r.status_code != 200:
            break
        data = r.json()
        if not isinstance(data, list) or not data:
            break
        items.extend(data)
        if len(data) < 100:
            break
        page += 1
    return items[:limit]

def fetch_issues(o: str, r: str, limit: int) -> List[Dict]:
    data = fetch_paginated(f'https://api.github.com/repos/{o}/{r}/issues', limit)
    out = []
    for it in data:
        if 'pull_request' in it:
            continue
        title, body = it.get('title',''), it.get('body','')
        content = f"[Issue #{it.get('number')}] {title}\n\n{body}".strip()
        out.append({'file': f'github:issue:{it.get("number")}', 'chunk_id': f'issue_{it.get("number")}',
                    'content': content, 'type': 'issue', 'size': len(content), 'lines': content.count('\n')+1,
                    'source': 'issue', 'url': it.get('html_url')})
    return out

def fetch_prs(o: str, r: str, limit: int) -> List[Dict]:
    data = fetch_paginated(f'https://api.github.com/repos/{o}/{r}/pulls', limit)
    out = []
    for it in data:
        title, body = it.get('title',''), it.get('body','')
        content = f"[PR #{it.get('number')}] {title}\n\n{body}".strip()
        out.append({'file': f'github:pr:{it.get("number")}', 'chunk_id': f'pr_{it.get("number")}',
                    'content': content, 'type': 'pr', 'size': len(content), 'lines': content.count('\n')+1,
                    'source': 'pr', 'url': it.get('html_url')})
    return out

def fetch_security(o: str, r: str, limit: int) -> List[Dict]:
    resp = requests.get(f'https://api.github.com/repos/{o}/{r}/security/advisories', headers=gh_headers(), params={'per_page':100}, timeout=30)
    if resp.status_code != 200:
        return []
    data = resp.json()
    if not isinstance(data, list):
        return []
    out = []
    for a in data[:limit]:
        summary, desc = a.get('summary',''), a.get('description','')
        content = f"[Security] {summary}\n\n{desc}".strip()
        out.append({'file': f'github:security:{a.get("ghsa_id")}', 'chunk_id': f'sec_{a.get("ghsa_id")}',
                    'content': content, 'type':'security', 'size': len(content), 'lines': content.count('\n')+1,
                    'source':'security', 'url': a.get('html_url'), 'severity': a.get('severity')})
    return out

# ---------- persistence helpers ----------

def ensure_layout(base_dir: Path):
    (base_dir / 'repo').mkdir(parents=True, exist_ok=True)
    (base_dir / 'data' / 'issues').mkdir(parents=True, exist_ok=True)
    (base_dir / 'data' / 'prs').mkdir(parents=True, exist_ok=True)
    (base_dir / 'data' / 'security').mkdir(parents=True, exist_ok=True)
    (base_dir / 'data' / 'chunks').mkdir(parents=True, exist_ok=True)
    (base_dir / 'rag_embeddings').mkdir(parents=True, exist_ok=True)

def persist_items(items: List[Dict], dest: Path, prefix: str):
    dest.mkdir(parents=True, exist_ok=True)
    for it in items:
        ident = it.get('chunk_id') or it.get('file','').split(':')[-1]
        fn = dest / f"{prefix}_{ident}.md"
        try:
            fn.write_text(it['content'], encoding='utf-8')
        except Exception:
            pass


def persist_chunks_text(chunks: List[Dict], chunks_dir: Path):
    for c in chunks:
        fn = chunks_dir / f"{c['chunk_id']}.txt"
        try:
            fn.write_text(c['content'], encoding='utf-8')
        except Exception:
            pass

# ---------- build vector store ----------

def build_vector_store(chunks: List[Dict], model_name: str, embed_dir: Path):
    docs: List[Document] = []
    for c in chunks:
        meta = {k: v for k, v in c.items() if k != 'content'}
        docs.append(Document(page_content=c['content'], metadata=meta))
    embeddings = HuggingFaceEmbeddings(model_name=model_name, encode_kwargs={'normalize_embeddings': True})
    print(f"[cyan]Embedding {len(docs)} docs with {model_name} ...")
    vs = FAISS.from_documents(docs, embeddings)
    embed_dir.mkdir(parents=True, exist_ok=True)
    vs.save_local(str(embed_dir))
    with (embed_dir / 'meta.jsonl').open('w', encoding='utf-8') as f:
        for c in chunks:
            f.write(json.dumps(c, ensure_ascii=False) + '\n')
    cfg = {
        'embedding_model': model_name,
        'count': len(chunks),
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'sources': sorted(list({c['source'] for c in chunks}))
    }
    with (embed_dir / 'config.json').open('w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    print(f"[green]Vector store saved: {embed_dir}")

# ---------- main ----------

def main():  # pragma: no cover
    parser = argparse.ArgumentParser(description='Build RAG vector store (new separated layout)')
    parser.add_argument('--repo-url', required=True)
    parser.add_argument('--root-dir', default='./kb')
    parser.add_argument('--embedding-model', default='sentence-transformers/all-mpnet-base-v2')
    parser.add_argument('--max-files', type=int, default=1500)
    parser.add_argument('--no-remote', action='store_true', help='Disable fetching issues/pr/security')
    parser.add_argument('--rebuild', action='store_true')
    parser.add_argument('--save-chunks', action='store_true', help='Persist each chunk text under data/chunks')
    args = parser.parse_args()

    root = Path(args.root_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    repo_name = _normalize_repo_name(args.repo_url)
    base_dir = root / repo_name
    ensure_layout(base_dir)

    clone_dir = base_dir / 'repo'
    embed_dir = base_dir / 'rag_embeddings'
    data_dir = base_dir / 'data'

    # legacy detection
    legacy_dirs = ['code', 'issue', 'pr', 'security']
    for ld in legacy_dirs:
        if (base_dir / ld).exists():
            print(f"[yellow]Legacy directory detected: {ld}/ (deprecated). New layout uses repo/ & data/*")

    if embed_dir.exists() and (embed_dir / 'index.faiss').exists() and not args.rebuild:
        print('[green]Existing embeddings found (use --rebuild to force). Abort build.')
        return
    if args.rebuild and embed_dir.exists():
        print('[yellow]Rebuilding: removing old embedding directory')
        shutil.rmtree(embed_dir)
        embed_dir.mkdir(parents=True, exist_ok=True)

    clone_or_update(args.repo_url, clone_dir)

    files = collect_files(clone_dir, args.max_files)
    print(f"[cyan]Collected files: {len(files)}")

    chunks: List[Dict] = []
    for f in tqdm(files, desc='Chunking'):
        chunks.extend(chunk_file(f))

    if not args.no_remote:
        owner_repo = parse_owner_repo(args.repo_url)
        if owner_repo:
            o, r = owner_repo
            print('[cyan]Fetching remote metadata (issues/pr/security)...')
            try:
                issues = fetch_issues(o, r, 150)
                prs = fetch_prs(o, r, 100)
                secs = fetch_security(o, r, 40)
                print(f"  issues={len(issues)} prs={len(prs)} security={len(secs)}")
                chunks.extend(issues + prs + secs)
                persist_items(issues, data_dir / 'issues', 'issue')
                persist_items(prs, data_dir / 'prs', 'pr')
                persist_items(secs, data_dir / 'security', 'sec')
            except Exception as e:  # pragma: no cover
                print(f"[red]Remote metadata fetch failed: {e}")
        else:
            print('[red]Owner/repo parse failed; skip remote metadata.')

    # dedup
    seen, dedup = set(), []
    for c in chunks:
        h = md5(c['content'])
        if h in seen:
            continue
        seen.add(h)
        c['content_hash'] = h
        dedup.append(c)
    print(f"[magenta]Chunks total={len(chunks)} dedup={len(dedup)}")
    if not dedup:
        print('[red]No content to embed; abort.')
        return

    if args.save_chunks:
        persist_chunks_text(dedup, data_dir / 'chunks')

    build_vector_store(dedup, args.embedding_model, embed_dir)

if __name__ == '__main__':  # pragma: no cover
    main()
