#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
import hashlib
import difflib
import subprocess
import shlex
from configparser import ConfigParser
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from contextlib import contextmanager
import textwrap

# Banner shown only on -h/--help output

APP_NAME = "nsesearch.py"

__version__ = "1.0.2"
VERSION = __version__
AUTHOR = "Tony Hayden"
GITHUB = "http://github.com/haydena23"
BANNER = r"""
 __    __   ______   ________   ______                                           __       
|  \  |  \ /      \ |        \ /      \                                         |  \      
| $$\ | $$|  $$$$$$\| $$$$$$$$|  $$$$$$\  ______    ______    ______    _______ | $$____  
| $$$\| $$| $$___\$$| $$__    | $$___\$$ /      \  |      \  /      \  /       \| $$    \ 
| $$$$\ $$ \$$    \ | $$  \    \$$    \ |  $$$$$$\  \$$$$$$\|  $$$$$$\|  $$$$$$$| $$$$$$$\
| $$\$$ $$ _\$$$$$$\| $$$$$    _\$$$$$$\| $$    $$ /      $$| $$   \$$| $$      | $$  | $$
| $$ \$$$$|  \__| $$| $$_____ |  \__| $$| $$$$$$$$|  $$$$$$$| $$      | $$_____ | $$  | $$
| $$  \$$$ \$$    $$| $$     \ \$$    $$ \$$     \ \$$    $$| $$       \$$     \| $$  | $$
 \$$   \$$  \$$$$$$  \$$$$$$$$  \$$$$$$   \$$$$$$$  \$$$$$$$ \$$        \$$$$$$$ \$$   \$$                                                                                     

"""

# --- Cache and config locations ---
CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "nsesearchrc.json"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "nsesearch"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
INDEX_PATH = CACHE_DIR / "index.json"
INDEX_VERSION = 6  # Bumped for hash-based change detection
MAX_REBUILDS = 3  # Prevent infinite rebuild loops

DEFAULT_NSE_DIRS = [
    "/usr/share/nmap/scripts",
    "/usr/local/share/nmap/scripts",
    "/opt/homebrew/opt/nmap/share/nmap/scripts",
    "/usr/local/opt/nmap/share/nmap/scripts",
]

def load_config() -> Dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}

def env_nse_dirs() -> List[str]:
    env = os.environ.get("NSE_PATH", "")
    return [p for p in env.split(os.pathsep) if p.strip()] if env else []

# ---------------- Data model ----------------

@dataclass
class ScriptMeta:
    name: str
    path: str
    description: str = ""
    categories: List[str] = None
    authors: List[str] = None
    args: List[str] = None
    references: List[str] = None
    service_hints: List[str] = None
    port_hints: List[int] = None
    dependencies: List[str] = None  # New: script dependencies
    updated_ts: float = 0.0
    content_hash: str = ""  # New: for change detection

    def to_dict(self) -> Dict:
        d = asdict(self)
        for k in ("categories", "authors", "args", "references", "service_hints", "port_hints", "dependencies"):
            if d[k] is None:
                d[k] = []
        d["description"] = (d.get("description") or "").strip()
        d["path"] = str(d.get("path") or "")
        d["name"] = str(d.get("name") or "")
        d["content_hash"] = str(d.get("content_hash") or "")
        return d

# ---------------- File scan ----------------

@contextmanager
def timeout_glob(max_files: int = 10000):
    """Limit rglob to prevent hangs on huge dirs."""
    count = 0
    def limited_rglob(p: Path, pattern: str):
        nonlocal count
        for f in p.rglob(pattern):
            if count >= max_files:
                raise TimeoutError(f"Exceeded max files ({max_files}) in {p}")
            count += 1
            yield f
    yield limited_rglob

def find_nse_files(dirs: Sequence[str]) -> List[Path]:
    paths: List[Path] = []
    seen = set()
    for d in dirs:
        p = Path(d)
        if not p.is_dir():
            continue
        try:
            with timeout_glob() as rglob:
                for f in rglob(p, "*.nse"):
                    try:
                        rp = f.resolve()
                    except Exception:
                        rp = f
                    if rp not in seen:
                        seen.add(rp)
                        paths.append(rp)
        except TimeoutError as e:
            print(f"[!] Warning: {e}", file=sys.stderr)
    return sorted(paths)

# ---------------- Parsing ----------------

TAG_LINE_RE = re.compile(r"^\s*--+\s*@(\w+)\s*:\s*(.+)$", re.IGNORECASE)
DOC_LINE_RE = re.compile(r"^\s*---\s*(.+)$")
CATEGORIES_LUA_RE = re.compile(r"categories\s*=\s*{([^}]*)}", re.IGNORECASE | re.DOTALL)
AUTHOR_LUA_RE = re.compile(r'author[s]?\s*=\s*(\{.*?\}|\[\[.*?\]\]|"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\')', re.IGNORECASE | re.DOTALL)
DESCRIPTION_LUA_RE = re.compile(r"description\s*=\s*(\[\[.*?\]\]|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')", re.IGNORECASE | re.DOTALL)
DEPENDENCIES_LUA_RE = re.compile(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)  # New: parse require()
HTML_TAG_RE = re.compile(r"<[^>]+>")
CODE_TAG_RE = re.compile(r"<code>(.*?)</code>", re.IGNORECASE)  # New: preserve <code>
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# --- Colors ---
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"
RESET = "\x1b[0m"

def _should_color(opt: str) -> bool:
    if opt == "always":
        return True
    if opt == "never":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def _compile_terms_regex(terms: List[str], *, case_sensitive: bool = False) -> Optional[re.Pattern]:
    terms = [t for t in (terms or []) if t]
    if not terms:
        return None
    
    uniq_lower = sorted(set(t.lower() for t in terms if not case_sensitive), key=lambda s: (-len(s), s))
    escaped = []
    for t in uniq_lower:
        if t in ('http', 'https'):
            # Special regex for http/https to avoid matching URLs
            escaped.append(r'(?<!\w)' + re.escape(t) + r'(?!://)(?!\w)')
        else:
            escaped.append(r'(?<!\w)' + re.escape(t) + r'(?!\w)')

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.compile("(" + "|".join(escaped) + ")", flags)
    except re.error:
        return None

def highlight_text(text: str, terms_re: Optional[re.Pattern], color_on: bool) -> str:
    if not color_on or not terms_re or not text:
        return text
    def repl(m):
        return f"{RED}{m.group(0)}{RESET}"
    return terms_re.sub(repl, text)

def highlight_lua(code: str) -> str:
    """Applies syntax highlighting to a string of Lua code."""
    keywords1 = r'\b(and|break|do|else|elseif|end|false|for|function|if|in|local|nil|not|or|repeat|return|then|true|until|while)\b'
    keywords2 = r'\b(nmap|shortport|stdnse|string|table|math|io|os|coroutine|package|debug|_G|_VERSION|vulns)\b'
    numbers = r'\b(0x[0-9a-fA-F]+|[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\b'
    comments = r'(--\[\[.*?\]\]|--[^\r\n]*)'
    strings = r'(\"(?:\\.|[^\"\\])*\"|\'(?:\\.|[^\'\\])*\'|\[\[.*?\]\])'

    token_spec = [
        ('COMMENT', comments),
        ('STRING', strings),
        ('KEYWORD1', keywords1),
        ('KEYWORD2', keywords2),
        ('NUMBER', numbers),
    ]
    master_re = re.compile('|'.join(f'(?P<{name}>{pattern})' for name, pattern in token_spec), re.DOTALL)
    colors = {
        'COMMENT': GREEN, 'STRING': YELLOW, 'KEYWORD1': BLUE,
        'KEYWORD2': CYAN, 'NUMBER': MAGENTA
    }
    def repl(m):
        kind = m.lastgroup
        value = m.group(kind)
        return f"{colors.get(kind, '')}{value}{RESET}" if kind in colors else value
    return master_re.sub(repl, code)

# Portrule hints
SHORTPORT_CALL_RE = re.compile(r"shortport\.(\w+)")
PORT_OR_SERVICE_RE = re.compile(r"shortport\.port_or_service\(([^)]*)\)|shortport\.service\(([^)]*)\)", re.IGNORECASE | re.DOTALL)
PORTNUMBER_RE = re.compile(r"shortport\.portnumber\(([^)]*)\)", re.IGNORECASE | re.DOTALL)

def strip_html(s: str) -> str:
    # Preserve <code> as backticks
    s = CODE_TAG_RE.sub(r"`\1`", s or "")
    return HTML_TAG_RE.sub("", s)

def parse_nse(path: Path) -> ScriptMeta:
    text = ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass

    description = ""
    authors: List[str] = []
    args: List[str] = []
    references: List[str] = []
    dependencies: List[str] = []  # New

    # 1) @tags anywhere
    for line in (text or "").splitlines():
        m = TAG_LINE_RE.match(line)
        if not m:
            continue
        tag, val = m.group(1).lower(), m.group(2).strip()
        if tag in ("desc", "description", "shortdesc", "summary"):
            description += ((" " if description else "") + val)
        elif tag in ("author", "authors"):
            for a in re.split(r"[;,]", val):
                a = a.strip()
                if a:
                    authors.append(a)
        elif tag in ("arg", "args", "script-args"):
            if val:
                args.append(val)
        elif tag in ("ref", "refs", "reference", "references", "see"):
            if val:
                references.append(val)

    # 2) categories
    cats: List[str] = []
    m = CATEGORIES_LUA_RE.search(text or "")
    if m:
        inner = m.group(1)
        for c in inner.split(","):
            c = c.strip().strip("\"'")
            if c:
                cats.append(c)

    # 2b) author[s] = ... (Improved for nested tables)
    am = AUTHOR_LUA_RE.search(text or "")
    if am:
        aval = am.group(1).strip()
        extracted = []
        if aval.startswith("{"):
            # Handle nested tables conservatively
            extracted = re.findall(r'["\']((?:\\.|[^"\'])+)["\']', aval)
        elif aval.startswith("[[") and aval.endswith("]]"):
            inner = aval[2:-2]
            extracted = [inner]
        elif (aval.startswith('"') and aval.endswith('"')) or (aval.startswith("'") and aval.endswith("'")):
            inner = aval[1:-1]
            extracted = [inner]
        for a in extracted:
            a = re.sub(r'\s*<[^>]+>', '', a).strip()
            for piece in re.split(r'[;,]| and ', a):
                piece = piece.strip()
                if piece:
                    authors.append(piece)

    # 2c) dependencies = ... (New)
    for mdep in DEPENDENCIES_LUA_RE.finditer(text or ""):
        dep = mdep.group(1).strip()
        if dep:
            dependencies.append(dep)

    # 3) description assignment
    if not description:
        dm = DESCRIPTION_LUA_RE.search(text or "")
        if dm:
            dval = dm.group(1)
            if dval.startswith("[[") and dval.endswith("]]"):
                dval = dval[2:-2]
            elif (dval.startswith('"') and dval.endswith('"')) or (dval.startswith("'") and dval.endswith("'")):
                dval = dval[1:-1]
            description = dval.strip()

    # 5) portrule hints
    service_hints: List[str] = []
    port_hints: List[int] = []
    for msp in SHORTPORT_CALL_RE.finditer(text or ""):
        func = msp.group(1).lower()
        if func not in ("port_or_service", "portnumber", "service"):
            service_hints.append(func)

    def _extract_args_to_ports_services(argstr: str):
        services = re.findall(r'[\'"]([A-Za-z0-9_\-\.]+)[\'"]', argstr or "")
        nums = [int(n) for n in re.findall(r"\b\d{1,5}\b", argstr or "") if 0 < int(n) <= 65535]
        return services, nums

    for mpos in PORT_OR_SERVICE_RE.finditer(text or ""):
        argstr = mpos.group(1) or mpos.group(2) or ""
        s, n = _extract_args_to_ports_services(argstr)
        service_hints.extend(s)
        port_hints.extend(n)

    for mpn in PORTNUMBER_RE.finditer(text or ""):
        s, n = _extract_args_to_ports_services(mpn.group(1))
        port_hints.extend(n)

    service_hints = sorted(set(x.lower() for x in service_hints))
    port_hints = sorted(set(port_hints))

    # 4) NSEdoc fallback
    if not description:
        doc_lines: List[str] = []
        for ln in (text or "").splitlines():
            mdoc = DOC_LINE_RE.match(ln)
            if mdoc:
                doc_lines.append(mdoc.group(1).strip())
            elif doc_lines:
                break
        if doc_lines:
            description = " ".join(doc_lines).strip()

    # Compute content hash
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""

    name = path.stem
    stat = path.stat() if path.exists() else None
    updated_ts = stat.st_mtime if stat else 0.0
    return ScriptMeta(
        name=name,
        path=str(path),
        description=strip_html(description).replace("\n", " ").strip(),
        categories=sorted(set(cats)),
        authors=sorted(set(authors)),
        args=sorted(set(args)),
        references=sorted(set(references)),
        service_hints=service_hints,
        port_hints=port_hints,
        dependencies=sorted(set(dependencies)),
        updated_ts=updated_ts,
        content_hash=content_hash,
    )

# ---------------- Index ----------------

def build_index(search_dirs: Sequence[str]) -> Dict[str, Dict]:
    files = find_nse_files(search_dirs)
    index: Dict[str, Dict] = {
        "_version": INDEX_VERSION,
        "_built_ts": time.time(),
        "_dirs": list(search_dirs),
        "scripts": {}
    }
    for f in files:
        meta = parse_nse(f)
        index["scripts"][meta.name] = meta.to_dict()
    return index

def load_index() -> Optional[Dict]:
    if not INDEX_PATH.exists():
        return None
    try:
        with INDEX_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("_version") != INDEX_VERSION:
            return None
        return data
    except Exception:
        return None

def save_index(idx: Dict) -> None:
    tmp = INDEX_PATH.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(idx, fh, indent=2, ensure_ascii=False)
    tmp.replace(INDEX_PATH)

def ensure_index(update: bool, extra_dirs: Sequence[str], config_dirs: Sequence[str]) -> Dict:
    idx = None if update else load_index()
    dirs = list(dict.fromkeys(env_nse_dirs() + DEFAULT_NSE_DIRS + list(extra_dirs) + list(config_dirs)))
    if idx and sorted(idx.get("_dirs", [])) != sorted(dirs):
        idx = None  # Force rebuild if dirs changed
    if idx is None:
        rebuild_count = 0
        while rebuild_count < MAX_REBUILDS:
            idx = build_index(dirs)
            scripts = idx.get("scripts", {})
            total = len(scripts)
            empties = sum(1 for v in scripts.values() if not (v.get("description") or "").strip())
            if total > 0 and (empties / total) > 0.6:
                rebuild_count += 1
                print(f"[!] Warning: High empty description ratio ({empties}/{total}), rebuilding ({rebuild_count}/{MAX_REBUILDS})", file=sys.stderr)
                continue
            save_index(idx)
            break
        else:
            print(f"[!] Error: Failed to build index after {MAX_REBUILDS} attempts", file=sys.stderr)
            sys.exit(1)
    return idx

# ---------------- Search ----------------

def normalize(s: str) -> str:
    return (s or "").lower()

def parse_query(query: str) -> List[List[str]]:
    """
    Parses a query like "http wordpress OR smb brute" into OR-groups of AND-terms.
    Result for the example: [['http', 'wordpress'], ['smb', 'brute']]
    """
    if not query:
        return []
    or_groups = re.split(r'\s+OR\s+', query, flags=re.IGNORECASE)
    return [re.split(r'\s+', group.strip()) for group in or_groups if group.strip()]

def matches(meta: Dict, query: str, regex: Optional[re.Pattern], exact: bool,
            category_filter: Optional[List[str]], exclude_categories: Optional[List[str]],
            author_filter: Optional[List[str]], exclude_authors: Optional[List[str]],
            service_filter: Optional[List[str]], port_filter: Optional[set],
            *, name_only: bool = False, case_sensitive: bool = False) -> bool:
    # Category/author/service/port filters
    if category_filter:
        mc = [normalize(x) for x in meta.get("categories", [])]
        if not any(normalize(c) in mc for c in category_filter):
            return False
    if exclude_categories:
        mc = [normalize(x) for x in meta.get("categories", [])]
        if any(normalize(c) in mc for c in exclude_categories):
            return False
    if author_filter:
        authors = normalize(", ".join(meta.get("authors", [])))
        if not any(normalize(a) in authors for a in author_filter):
            return False
    if exclude_authors:
        authors = normalize(", ".join(meta.get("authors", [])))
        if any(normalize(a) in authors for a in exclude_authors):
            return False
    if service_filter:
        services = set(normalize(s) for s in meta.get("service_hints", []) + _name_service_hints(meta.get("name", "")))
        if not any(normalize(s) in services for s in service_filter):
            return False
    if port_filter:
        if not _script_matches_ports(meta, port_filter):
            return False

    hay = meta.get("name", "") if name_only else " ".join(filter(None, [
        meta.get("name", ""),
        meta.get("description", ""),
        " ".join(meta.get("categories", [])),
        " ".join(meta.get("authors", [])),
        " ".join(meta.get("args", [])),
        " ".join(meta.get("references", [])),
        meta.get("path", ""),
    ]))

    # Regex search is an AND condition with the query
    if regex:
        try:
            if not regex.search(hay):
                return False
        except Exception:
            return False

    # Text query search
    if query:
        or_groups = parse_query(query)
        hay_use = hay if case_sensitive else hay.lower()
        hay_tokens = set(re.findall(r"\b\w+\b", hay_use)) if exact else None

        # Script matches if ANY of the OR groups are fully satisfied
        for and_terms in or_groups:
            group_match = True
            # ALL terms in this group must be present
            for term in and_terms:
                term_use = term if case_sensitive else term.lower()
                term_found = False
                if exact:
                    if term_use in hay_tokens:
                        term_found = True
                else:  # <<<< SURGICAL FIX START >>>>
                    pattern = ''
                    # If the term is http or https, add a negative lookahead to exclude URLs
                    if term_use in ('http', 'https'):
                        # Match 'http' or 'https' but NOT if it's followed by '://'
                        pattern = r'(?<!\w)' + re.escape(term_use) + r'(?!://)(?!\w)'
                    else:
                        # For all other terms, use the standard whole-word match
                        pattern = r'(?<!\w)' + re.escape(term_use) + r'(?!\w)'
                    
                    if re.search(pattern, hay_use):
                        term_found = True
                # <<<< SURGICAL FIX END >>>>
                
                if not term_found:
                    group_match = False
                    break  # This AND group fails
            
            if group_match:
                return True  # One of the OR groups succeeded
        
        return False # No OR groups matched
        
    return True

# ---------------- Rendering ----------------

def visible_len(s: str) -> int:
    return len(ANSI_RE.sub("", str(s)))

def ljust_visible(s: str, width: int) -> str:
    s = str(s)
    pad = max(0, width - visible_len(s))
    return s + (" " * pad)

def write_output(text: str, out_path: Optional[str], append: bool = False, quiet: bool = False) -> None:
    if out_path and out_path != "-":
        clean = ANSI_RE.sub("", text or "")
        mode = "a" if append else "w"
        try:
            with open(out_path, mode, encoding="utf-8") as fh:
                fh.write(clean)
                if not clean.endswith("\n"):
                    fh.write("\n")
            if not quiet:
                print(f"[+] Wrote output to {out_path}", file=sys.stderr)
        except Exception as e:
            print(f"[!] Failed to write to {out_path}: {e}", file=sys.stderr)
    else:
        print(text)

def _distribute_proportional_widths(n_cols: int, max_width: int, mins: Optional[List[int]] = None, caps: Optional[List[int]] = None) -> List[int]:
    """Distributes width proportionally, growing from minimums. Good for wide tables."""
    gaps = 2 * (n_cols - 1)
    usable = max_width - gaps
    if mins is None:
        mins = [8] * n_cols
    if caps is None:
        caps = [9999] * n_cols
    widths = mins[:]
    remaining = max(0, usable - sum(widths))
    idx = 0
    while remaining > 0 and any(widths[i] < caps[i] for i in range(n_cols)):
        if widths[idx] < caps[idx]:
            inc = min(4, caps[idx] - widths[idx], remaining)
            widths[idx] += inc
            remaining -= inc
        idx = (idx + 1) % n_cols
    return widths

def _distribute_equal_widths(n_cols: int, max_width: int) -> List[int]:
    """Distributes width equally. Good for very narrow tables."""
    if n_cols <= 0: return []
    gaps = 2 * (n_cols - 1)
    usable = max(n_cols, max_width - gaps)
    base_width = usable // n_cols
    remainder = usable % n_cols
    widths = [base_width] * n_cols
    for i in range(remainder):
        widths[i] += 1
    return widths

def _wrap_plain(text: str, width: int) -> List[str]:
    if width <= 0:
        return [text]
    text = text or ""
    return textwrap.wrap(text, width=width, replace_whitespace=False, drop_whitespace=False, break_long_words=True, break_on_hyphens=False) or [""]

def _render_table_4col(rows: List[List[str]], headers: List[str], max_width: int, with_separators: bool = True) -> str:
    mins = [14, 14, 24, 20]
    caps = [32, 32, 9999, 60]
    total_min_width = sum(mins) + (2 * (len(mins) - 1))
    
    # If the requested width is too small for our preferred proportions,
    # fall back to a generic, equal-width distribution.
    if max_width < total_min_width:
        return _render_table_generic(rows, headers, max_width)

    widths = _distribute_proportional_widths(4, max_width, mins=mins, caps=caps)
    def fmt_line(parts: List[str]) -> str:
        return "  ".join(ljust_visible(parts[i], widths[i]) for i in range(4))
    out: List[str] = []
    out.append(fmt_line(headers))
    out.append(fmt_line(["-"*w for w in widths]))
    for r in rows:
        script, cats, desc, path = r[0], r[1], r[2], r[3]
        cols = [
            _wrap_plain(script, widths[0]),
            _wrap_plain(cats, widths[1]),
            _wrap_plain(desc, widths[2]),
            _wrap_plain(path, widths[3]),
        ]
        height = max(len(c) for c in cols)
        for i in range(height):
            out.append(fmt_line([cols[c][i] if i < len(cols[c]) else "" for c in range(4)]))
        if with_separators and height > 1:
            out.append(fmt_line(["-"*w for w in widths]))
    if with_separators and out and out[-1].strip().strip("-") == "":
        out.pop()
    return "\n".join(out)

def _render_table_generic(rows: List[List[str]], headers: List[str], max_width: int) -> str:
    n = len(headers)
    widths = _distribute_equal_widths(n, max_width)
    def fmt_line(parts: List[str]) -> str:
        return "  ".join(ljust_visible(parts[i], widths[i]) for i in range(n))
    out: List[str] = []
    out.append(fmt_line(headers))
    out.append(fmt_line(["-"*w for w in widths]))
    for r in rows:
        wrapped_cols = [_wrap_plain(r[i], widths[i]) for i in range(n)]
        height = max(len(col) for col in wrapped_cols)
        for i in range(height):
            out.append(fmt_line([wrapped_cols[c][i] if i < len(wrapped_cols[c]) else "" for c in range(n)]))
        if height > 1:
            out.append(fmt_line(["-"*w for w in widths]))
    if out and out[-1].strip().strip("-") == "":
        out.pop()
    return "\n".join(out)

def tabulate(rows: List[List[str]], headers: List[str]) -> str:
    try:
        max_width = shutil.get_terminal_size(fallback=(120, 20)).columns
    except Exception:
        max_width = 120
    
    if len(headers) == 4:
        return _render_table_4col(rows, headers, max_width, with_separators=True)
    else:
        return _render_table_generic(rows, headers, max_width)

# -------- Structured output helpers --------

def _format_rows(rows: List[List[str]], headers: List[str], fmt: str, color_opt: str, terms_re: Optional[re.Pattern]) -> str:
    fmt = (fmt or "table").lower()
    if fmt == "table":
        # The `max_width` logic is now handled inside the tabulate function
        return tabulate(rows, headers=headers)

    objs = [{headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers))} for row in rows]

    if fmt == "json":
        text = json.dumps(objs, indent=2, ensure_ascii=False)
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text

    if fmt == "ndjson":
        lines = [json.dumps(o, ensure_ascii=False) for o in objs]
        if color_opt == "always" and terms_re:
            lines = [highlight_text(line, terms_re, True) for line in lines]
        return "\n".join(lines)

    if fmt in ("yaml", "yml"):
        output_lines = []
        for obj in objs:
            item_lines = []
            for i, (key, value) in enumerate(obj.items()):
                value_str = str(value)
                line = ""
                # Use literal block scalar `|` for multiline strings for readability
                if "\n" in value_str:
                    # Indent the multiline value block correctly under its key
                    indented_value = textwrap.indent(value_str, "    ")
                    line = f"  {key}:\n{indented_value}"
                    # A better style for multiline is using the literal block scalar
                    line = f"  {key}: |-\n{textwrap.indent(value_str, '    ')}"
                else:
                    # For single-line values, use JSON dumps to safely quote special characters
                    final_value = json.dumps(value_str)
                    line = f"  {key}: {final_value}"

                # The very first line of the object representation gets the list marker `-`
                if i == 0:
                    # Replace the first two spaces of indentation with "- "
                    line = f"- {line.lstrip()}"
                
                item_lines.append(line)
            output_lines.extend(item_lines)
            
        text = "\n".join(output_lines)
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text

    if fmt in ("csv", "tsv"):
        import io, csv
        sep = "," if fmt == "csv" else "\t"
        sio = io.StringIO()
        w = csv.writer(sio, delimiter=sep)
        w.writerow(headers)
        for r in rows:
            w.writerow([r[i] if i < len(r) else "" for i in range(len(headers))])
        text = sio.getvalue().rstrip("\n")
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text

    if fmt == "xml":
        from xml.etree.ElementTree import Element, SubElement, tostring
        root = Element("results")
        for obj in objs:
            e = SubElement(root, "row")
            for k, v in obj.items():
                child = SubElement(e, k.replace(" ", "_").lower())
                v = str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")
                child.text = v
        try:
            text = tostring(root, encoding="unicode")
        except Exception:
            text = tostring(root, encoding="utf-8").decode("utf-8")
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text

    return tabulate(rows, headers=headers)

def _format_paths(paths: List[str], fmt: str, color_opt: str, terms_re: Optional[re.Pattern]) -> str:
    fmt = (fmt or "table").lower()
    if fmt == "table":
        rows = [[p] for p in paths]
        return tabulate(rows, headers=["Path"])
    if fmt == "json":
        text = json.dumps(paths, indent=2, ensure_ascii=False)
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text
    if fmt == "ndjson":
        lines = [json.dumps(p, ensure_ascii=False) for p in paths]
        if color_opt == "always" and terms_re:
            lines = [highlight_text(line, terms_re, True) for line in lines]
        return "\n".join(lines)
    if fmt in ("yaml", "yml"):
        text = "\n".join(f"- {p}" for p in paths)
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text
    if fmt in ("csv", "tsv"):
        import io, csv
        sep = "," if fmt == "csv" else "\t"
        sio = io.StringIO()
        w = csv.writer(sio, delimiter=sep)
        w.writerow(["Path"])
        for pth in paths:
            w.writerow([pth])
        text = sio.getvalue().rstrip("\n")
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text
    if fmt == "xml":
        from xml.etree.ElementTree import Element, SubElement, tostring
        root = Element("paths")
        for pth in paths:
            child = SubElement(root, "path")
            child.text = pth.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")
        try:
            text = tostring(root, encoding="unicode")
        except Exception:
            text = tostring(root, encoding="utf-8").decode("utf-8")
        return highlight_text(text, terms_re, _should_color(color_opt)) if color_opt == "always" else text
    rows = [[p] for p in paths]
    return tabulate(rows, headers=["Path"])

# Service-to-port hints (expanded)
SERVICE_PORTS = {
    "http": {80, 81, 82, 88, 8000, 8008, 8080, 8081, 8088, 8888},
    "https": {443, 8443, 9443},
    "ssl": {443, 8443, 9443},
    "tls": {443, 8443, 9443},
    "smb": {139, 445},
    "microsoft-ds": {445},
    "mysql": {3306},
    "mssql": {1433, 1434},
    "postgres": {5432},
    "postgresql": {5432},
    "oracle": {1521},
    "tns": {1521},
    "redis": {6379},
    "memcached": {11211},
    "mongodb": {27017},
    "ssh": {22},
    "telnet": {23},
    "ftp": {21},
    "dns": {53},
    "ntp": {123},
    "smtp": {25, 465, 587, 2525},
    "pop3": {110, 995},
    "imap": {143, 993},
    "rdp": {3389},
    "vnc": {5900},
    "snmp": {161, 162},
    "ldap": {389, 636},
    "rpc": {111},
    "jdwp": {8000, 5005, 8787},
    "rtsp": {554},
    "sip": {5060, 5061},
    "amqp": {5672, 5671},
    "coap": {5683, 5684},
    "nfs": {2049},
    "kubernetes": {6443},
    "docker": {2375, 2376},
    "elasticsearch": {9200, 9300},
    "rabbitmq": {5672, 15672},
}

def _name_service_hints(name: str) -> List[str]:
    pre = (name or "").split("-", 1)[0].lower()
    hints = []
    if pre in SERVICE_PORTS:
        hints.append(pre)
    if pre == "https":
        hints.extend(["https", "ssl", "http"])
    if pre.startswith("http"):
        hints.append("http")
    if pre.startswith("ssl") or pre.startswith("tls") or pre.startswith("https"):
        hints.extend(["ssl", "tls", "https"])
    return sorted(set(hints))

def _ports_for_services(services: List[str]) -> set:
    ports = set()
    for s in services or []:
        ports |= SERVICE_PORTS.get(s.lower(), set())
    return ports

def _parse_ports_arg(ports_arg: str) -> Optional[set]:
    if not ports_arg:
        return None
    result = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if not (0 < a <= 65535 and 0 < b <= 65535):
                    print(f"[!] Warning: Invalid port range {part} (ports must be 1-65535)", file=sys.stderr)
                    continue
                if b - a > 10000:
                    print(f"[!] Warning: Port range {part} too large (>10000)", file=sys.stderr)
                    continue
                result.update(range(a, b+1))
            except Exception:
                print(f"[!] Warning: Invalid port range {part}", file=sys.stderr)
                continue
        else:
            try:
                n = int(part)
                if 0 < n <= 65535:
                    result.add(n)
                else:
                    print(f"[!] Warning: Invalid port {part} (must be 1-65535)", file=sys.stderr)
            except Exception:
                print(f"[!] Warning: Invalid port {part}", file=sys.stderr)
                continue
    return result or None

def _script_matches_ports(meta: Dict, user_ports: set) -> bool:
    hint_ports = set(meta.get("port_hints") or [])
    hint_services = set((meta.get("service_hints") or []))
    hint_ports |= _ports_for_services(list(hint_services))
    hint_services |= set(_name_service_hints(meta.get("name", "")))
    hint_ports |= _ports_for_services(list(hint_services))
    return bool(hint_ports & user_ports)

# ---------------- Categories ----------------

CATEGORIES_INFO = {
    "info": "Informational checks; print general host/service details.",
    "auth": "Authentication checks; identify/bypass auth.",
    "broadcast": "Discovery via broadcast.",
    "brute": "Brute-force credential guessing.",
    "default": "Safe, useful defaults.",
    "discovery": "Gather target/network/service info.",
    "dos": "Denial-of-Service tests; may disrupt.",
    "exploit": "Actively exploit known vulnerabilities.",
    "external": "Uses external resources/services.",
    "fuzzer": "Protocol fuzzing for robustness testing.",
    "intrusive": "May be disruptive or against policy.",
    "malware": "Detect malware/backdoors/IOCs.",
    "safe": "Designed to be non-intrusive.",
    "version": "Assist/refine version detection.",
    "vuln": "Check and report known vulnerabilities.",
}

# ---------------- Output helpers ----------------

def render_results(matches_list: List[Dict], paths_only: bool, deps_only: bool, *,
                   color_opt: str = "auto",
                   terms_regex: Optional[re.Pattern] = None, regex: Optional[re.Pattern] = None,
                   out_format: str = "table") -> str:
    out_format = (out_format or "table").lower()
    if deps_only:
        rows = [[m["name"], ",".join(m.get("dependencies", []) or []) or "-"] for m in matches_list]
        text = _format_rows(rows, ["Script", "Dependencies"], out_format, color_opt, terms_regex)
        return text
    if paths_only:
        paths = [m["path"] for m in matches_list]
        return _format_paths(paths, out_format, color_opt, terms_regex)

    rows = []
    for m in matches_list:
        name = m["name"]
        path = m["path"]
        cats = ",".join(m.get("categories", []) or []) or "-"
        desc = strip_html((m.get("description", "") or "-").strip())
        rows.append([name, cats, desc, path])

    # Highlight matches in table output
    if out_format == "table" and _should_color(color_opt):
        # The main highlight should be from the user's search query terms
        if terms_regex:
            for row in rows:
                for i in range(len(row)):
                    row[i] = highlight_text(row[i], terms_regex, True)
        # Also highlight the specific regex if provided
        if regex:
            for row in rows:
                for i in range(len(row)):
                    row[i] = highlight_text(row[i], regex, True)

    return _format_rows(rows, ["Script", "Categories", "Description", "Path"], out_format, color_opt, terms_regex)

def open_script(idx: Dict, name_or_path: str) -> Optional[Path]:
    # Handles both a direct path and a script name from the index
    p = Path(name_or_path)
    if p.exists() and name_or_path.endswith(".nse"):
        return p
    meta = idx["scripts"].get(p.stem)
    if meta:
        return Path(meta["path"])
    return None

def build_nmap_command(matches_list: List[Dict], target: str, script_args: Optional[str], ports: Optional[str]) -> List[str]:
    names = ",".join(sorted(m["name"] for m in matches_list))
    parts = ["nmap"]
    if ports:
        parts.extend(["-p", ports])
    parts.extend(["--script", names])
    if script_args:
        parts.extend(["--script-args", script_args])
    parts.append(target)
    return parts

def diff_scripts(script1: Path, script2: Path, color_opt: str = "auto") -> str:
    try:
        text1 = script1.read_text(encoding="utf-8", errors="replace").splitlines()
        text2 = script2.read_text(encoding="utf-8", errors="replace").splitlines()
        diff_lines = list(difflib.unified_diff(text1, text2, fromfile=str(script1), tofile=str(script2)))

        if not _should_color(color_opt) or not diff_lines:
            return "\n".join(diff_lines)

        colorized_lines = []
        # A unified diff always has at least two header lines.
        # We treat them specially to avoid ambiguity with content lines that
        # might also start with '---' or '+++'.
        if len(diff_lines) > 0:
            colorized_lines.append(diff_lines[0]) # --- file_a
        if len(diff_lines) > 1:
            colorized_lines.append(diff_lines[1]) # +++ file_b

        # Process the rest of the lines based on their mandatory prefix.
        for line in diff_lines[2:]:
            if not line: continue
            if line.startswith('+'):
                colorized_lines.append(f"{GREEN}{line}{RESET}")
            elif line.startswith('-'):
                colorized_lines.append(f"{RED}{line}{RESET}")
            elif line.startswith('@@'):
                colorized_lines.append(f"{CYAN}{line}{RESET}")
            else:
                # This case handles context lines, which start with a space.
                colorized_lines.append(line)
        return "\n".join(colorized_lines)
    except Exception as e:
        return f"[!] Error generating diff: {e}"

# ---------------- CLI ----------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(f"{BANNER}"
        "NSE Search is a fast, offline indexer & searcher for Nmap NSE scripts.\n"
        "Find scripts by name, description, category, author, args, references,\n"
        "services, or ports; filter safely with exact/regex; colorize matches;\n"
        "export in table, JSON, YAML, CSV/TSV, XML, or NDJSON; diff scripts;\n"
        "and generate/run nmap commands.\n\n"
        f"Made by: {AUTHOR}  |  Version: {__version__}  |  GitHub: {GITHUB}\n"),
        epilog=f"""Examples:
  # Rebuild index and show summary
  {APP_NAME} --update

  # Search (space = AND, use OR for alternatives)
  {APP_NAME} http wordpress
  {APP_NAME} "http brute OR ftp brute"

  # Regex search (case-sensitive with --case-sensitive)
  {APP_NAME} -r "(?i)ftpd.*backdoor"

  # Filter by category, author, service, port
  {APP_NAME} -c vuln -a "hdm" --service http --port 80,443
  {APP_NAME} -c vuln --exclude-categories intrusive

  # List categories with descriptions and counts
  {APP_NAME} --list-categories

  # Show a script with Lua syntax highlighting
  {APP_NAME} --show http-title

  # Copy a script or diff two scripts with colorized output
  {APP_NAME} --copy http-title
  {APP_NAME} --diff http-title /path/to/http-title.nse

  # Show dependencies for matching scripts
  {APP_NAME} http-vuln --deps

  # Generate/run nmap command
  {APP_NAME} --run 8.8.8.8 --ports 80 -c vuln
  {APP_NAME} --exec 8.8.8.8 http --ports 80 --script-args "useragent=MyUA"

  # Paths-only output
  {APP_NAME} -p http

  # Exact word match (AND, optional OR)
  {APP_NAME} -x "ftp brute OR http"
  {APP_NAME} -x --name-only --case-sensitive "ftp-anon"

  # Save output
  {APP_NAME} http --out results.json --format json

  # Debug index stats
  {APP_NAME} --verbose http
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    action_group = p.add_mutually_exclusive_group()
    action_group.add_argument("--update", action="store_true", help="Rebuild the index now")
    action_group.add_argument("--show", help="Show a script's contents with syntax highlighting (by name or path)")
    action_group.add_argument("--copy", help="Copy a script to the current directory (by name or path)")
    action_group.add_argument("--list-categories", action="store_true", help="List all categories with descriptions and counts")
    action_group.add_argument("--run", metavar="TARGET", help="Print an nmap command to run matching scripts against TARGET")
    action_group.add_argument("--exec", metavar="TARGET", help="Run an nmap command for matching scripts against TARGET")
    action_group.add_argument("--diff", nargs=2, metavar=("SCRIPT1", "SCRIPT2"), help="Diff two scripts with colorized output (by name or path)")
    
    p.add_argument("query", nargs="*", help="Search terms (space = AND, use OR for alternatives, e.g., 'http brute')")
    p.add_argument("-r", "--regex", help="Regex search across name/desc/cats/authors/args/refs/deps")
    p.add_argument("-x", "--exact", action="store_true", help="Exact word match for query terms")
    p.add_argument("-c", "--categories", help="Filter by categories (comma-separated)")
    p.add_argument("-e", "--exclude-categories", help="Exclude categories (comma-separated)")
    p.add_argument("-a", "--authors", help="Filter by authors (comma-separated)")
    p.add_argument("-A", "--exclude-authors", help="Exclude authors (comma-separated)")
    p.add_argument("-s", "--service", help="Filter by service hints (comma-separated, e.g., http,ssl)")
    p.add_argument("-P", "--port", help="Filter by port hints (comma-separated, e.g., 80,443)")
    p.add_argument("-p", "--paths-only", action="store_true", help="Print only file paths")
    p.add_argument("--deps", action="store_true", help="Show script dependencies instead of full details")
    p.add_argument("-d", "--dirs", help="Additional directories to scan (OS-path-separated)")
    p.add_argument("--script-args", help="Arguments to pass to --script-args when using --run/--exec")
    p.add_argument("--ports", help="Ports for nmap -p when using --run/--exec (e.g., 80,443 or 1-1024)")
    p.add_argument("--sort-by", choices=["name", "updated", "category"], default="name", help="Sort results by field")
    p.add_argument("--format", choices=["table", "json", "yaml", "ndjson", "csv", "tsv", "xml"], default="table", help="Select output format")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="Colorize matches in output (default: auto)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output (alias for --color=never)")
    p.add_argument("--out", metavar="FILE", help="Write output to FILE instead of stdout")
    p.add_argument("--append", action="store_true", help="Append to FILE when used with --out")
    p.add_argument("--quiet", action="store_true", help="Suppress status messages")
    p.add_argument("--name-only", action="store_true", help="Limit matching to script names only")
    p.add_argument("--case-sensitive", action="store_true", help="Make matching case-sensitive (affects -x, terms, and regex)")
    p.add_argument("--verbose", action="store_true", help="Print debug info (index stats, parsed metadata)")
    p.add_argument("--version", action="version", version=f"%(prog)s v{VERSION}")

    # If run with no arguments, print usage and a helpful tip.
    is_no_args_run = (argv is None and len(sys.argv) == 1) or (argv is not None and not argv)
    if is_no_args_run:
        p.print_usage(sys.stderr)
        print(f"\n[i] No search query or action specified. Try `{APP_NAME} --help` for a list of all options.", file=sys.stderr)
        return 0

    args = p.parse_args(argv)

    # Argument validation for dependent arguments
    if (args.ports or args.script_args) and not (args.run or args.exec):
        misused_arg = "'--ports'" if args.ports else "'--script-args'"
        if args.ports and args.script_args:
            misused_arg = "'--ports' and '--script-args'"
        p.print_usage(sys.stderr)
        print(f"\n[!] Argument Error: {misused_arg} can only be used with --run or --exec.", file=sys.stderr)
        return 2

    # Normalize output format & color
    out_format = getattr(args, "format", "table").lower()
    if getattr(args, "no_color", False):
        args.color = "never"
    elif args.color == "auto" and os.environ.get("NO_COLOR"):
        args.color = "never"

    # Load config
    config = load_config()
    config_dirs = config.get("dirs", [])
    config_format = config.get("format", out_format)
    if config_format in ["table", "json", "yaml", "ndjson", "csv", "tsv", "xml"]:
        out_format = config_format

    extra_dirs: List[str] = []
    if args.dirs:
        extra_dirs = [d for d in args.dirs.split(os.pathsep) if d.strip()]

    idx = ensure_index(update=args.update, extra_dirs=extra_dirs, config_dirs=config_dirs)

    # If the action was just to update the index, we are done.
    if args.update:
        if not args.quiet:
            print(f"[+] Index successfully updated. Found {len(idx.get('scripts', {}))} scripts.", file=sys.stderr)
        return 0

    if args.verbose:
        scripts = idx.get("scripts", {})
        dirs = idx.get("_dirs", [])
        print(f"[+] Index: {len(scripts)} scripts, {len(dirs)} dirs", file=sys.stderr)
        print(f"[+] Cache: {INDEX_PATH}", file=sys.stderr)

    if args.show:
        path = open_script(idx, args.show)
        if not path or not path.exists():
            print(f"[!] Could not find script: {args.show}", file=sys.stderr)
            return 1
        content = path.read_text(encoding="utf-8", errors="replace")
        if _should_color(args.color):
            content = highlight_lua(content)
        write_output(content, args.out, args.append, args.quiet)
        return 0

    if args.copy:
        path = open_script(idx, args.copy)
        if not path or not path.exists():
            print(f"[!] Could not find script: {args.copy}", file=sys.stderr)
            return 1
        dst = Path.cwd() / path.name
        if dst.exists():
            print(f"[!] Destination already exists: {dst}", file=sys.stderr)
            return 1
        shutil.copy2(path, dst)
        if not args.quiet:
            print(f"[+] Copied to {dst}", file=sys.stderr)
        return 0

    if args.diff:
        script1_id, script2_id = args.diff[0], args.diff[1]
        path1 = open_script(idx, script1_id)
        if not path1 or not path1.exists():
            print(f"[!] Could not find first script: {script1_id}", file=sys.stderr)
            return 1
        path2 = open_script(idx, script2_id)
        if not path2 or not path2.exists():
            print(f"[!] Could not find second script: {script2_id}", file=sys.stderr)
            return 1
        diff = diff_scripts(path1, path2, color_opt=args.color)
        write_output(diff, args.out, args.append, args.quiet)
        return 0

    scripts: Dict[str, Dict] = idx["scripts"]

    if args.list_categories:
        counts: Dict[str, int] = {}
        for m in scripts.values():
            for c in m.get("categories", []) or []:
                counts[c] = counts.get(c, 0) + 1
        all_cats = sorted(set(counts.keys()) | set(CATEGORIES_INFO.keys()))
        rows = [[c, CATEGORIES_INFO.get(c, "-"), str(counts.get(c, 0))] for c in all_cats]
        text = _format_rows(rows, ["Category", "Description", "Count"], out_format, args.color, _compile_terms_regex(args.categories.split(",") if args.categories else [], case_sensitive=args.case_sensitive))
        write_output(text, args.out, args.append, args.quiet)
        return 0

    query_text = " ".join(args.query).strip()
    regex = None
    if args.regex:
        try:
            regex = re.compile(args.regex, 0 if args.case_sensitive else re.IGNORECASE)
        except re.error as e:
            print(f"[!] Bad regex: {e}", file=sys.stderr)
            return 2

    category_filter = [s.strip().lower() for s in args.categories.split(",")] if args.categories else None
    exclude_categories = [s.strip().lower() for s in args.exclude_categories.split(",")] if args.exclude_categories else None
    author_filter = [s.strip().lower() for s in args.authors.split(",")] if args.authors else None
    exclude_authors = [s.strip().lower() for s in args.exclude_authors.split(",")] if args.exclude_authors else None
    service_filter = [s.strip().lower() for s in args.service.split(",")] if args.service else None
    port_filter = _parse_ports_arg(args.port) if args.port else None

    if args.run or args.exec:
        if not any([args.query, args.regex, args.categories, args.authors, args.service, args.port]):
            category_filter = ["default"]
            if not args.quiet:
                print("[i] No search terms or filters; defaulting to category 'default'", file=sys.stderr)

    matches_list = []
    for meta in scripts.values():
        if matches(meta, query_text, regex, args.exact, category_filter, exclude_categories,
                   author_filter, exclude_authors, service_filter, port_filter,
                   name_only=args.name_only, case_sensitive=args.case_sensitive):
            matches_list.append(meta)

    def rank(m: Dict) -> Tuple[int, int, str]:
        hay_name = m["name"]
        hay_desc = m.get("description", "")
        hay_cats = " ".join(m.get("categories", []))
        hay_authors = " ".join(m.get("authors", []))
        if not args.case_sensitive:
            hay_name_cmp = hay_name.lower()
            hay_desc_cmp = hay_desc.lower()
            hay_cats_cmp = hay_cats.lower()
            hay_authors_cmp = hay_authors.lower()
            q = query_text.lower()
        else:
            hay_name_cmp = hay_name
            hay_desc_cmp = hay_desc
            hay_cats_cmp = hay_cats
            hay_authors_cmp = hay_authors
            q = query_text
        primary = 0
        if q:
            if hay_name_cmp.find(q) != -1:
                primary = -3
            elif not args.name_only and hay_desc_cmp.find(q) != -1:
                primary = -2
            elif not args.name_only and (hay_cats_cmp.find(q) != -1 or hay_authors_cmp.find(q) != -1):
                primary = -1
        secondary = m.get("updated_ts", 0) if args.sort_by == "updated" else 0
        tertiary = hay_name.lower()
        return (primary, -int(secondary), tertiary)

    if args.sort_by == "category":
        matches_list.sort(key=lambda m: (",".join(m.get("categories", [])).lower(), m["name"].lower()))
    else:
        matches_list.sort(key=rank)

    if args.run or args.exec:
        if not matches_list:
            print("[!] No matching scripts to run.", file=sys.stderr)
            return 1
        user_ports = _parse_ports_arg(args.ports) if args.ports else None
        if user_ports:
            narrowed = [m for m in matches_list if _script_matches_ports(m, user_ports)]
            if narrowed:
                matches_list = narrowed
        
        target = args.run or args.exec
        # This regex is a reasonable check for valid hostnames/IPs and prevents shell metacharacters.
        if not re.match(r"^[a-zA-Z0-9\.\-:_/]+$", target):
            print(f"[!] Error: Invalid or unsafe target specified: '{target}'. Target contains disallowed characters.", file=sys.stderr)
            return 1
            
        cmd_list = build_nmap_command(matches_list, target, args.script_args, args.ports)
        if args.run:
            cmd_str = shlex.join(cmd_list)
            write_output(cmd_str, args.out, args.append, args.quiet)
            return 0
        else:
            try:
                # Using shell=False and passing a list of args is the correct, safe way to call subprocesses.
                result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, check=False)
                output = result.stdout + result.stderr
                write_output(output, args.out, args.append, args.quiet)
                return result.returncode
            except FileNotFoundError:
                print("[!] Error: 'nmap' command not found. Is it in your system's PATH?", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"[!] Failed to execute: {e}", file=sys.stderr)
                return 1

    query_terms = re.findall(r"\S+", query_text) if query_text else []
    if args.categories:
        query_terms += [t.strip() for t in args.categories.split(",") if t.strip()]
    if args.authors:
        query_terms += [t.strip() for t in args.authors.split(",") if t.strip()]
    if args.service:
        query_terms += [t.strip() for t in args.service.split(",") if t.strip()]
    terms_re = _compile_terms_regex(query_terms, case_sensitive=args.case_sensitive)

    out_text = render_results(matches_list, args.paths_only, args.deps,
                             color_opt=args.color, terms_regex=terms_re, regex=regex, out_format=out_format)
    write_output(out_text, args.out, args.append, args.quiet)
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)