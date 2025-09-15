#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Banner shown only on -h/--help output

APP_NAME = "nsesearch.py"

__version__ = "1.0.1"
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

# --- Cache location (use nsesearch, not nse-search) ---
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "nsesearch"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
INDEX_PATH = CACHE_DIR / "index.json"
INDEX_VERSION = 5  # bump when index structure/logic changes

DEFAULT_NSE_DIRS = [
    "/usr/share/nmap/scripts",
    "/usr/local/share/nmap/scripts",
    "/opt/homebrew/opt/nmap/share/nmap/scripts",
    "/usr/local/opt/nmap/share/nmap/scripts",
]

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
    updated_ts: float = 0.0

    def to_dict(self) -> Dict:
        d = asdict(self)
        for k in ("categories", "authors", "args", "references", "service_hints", "port_hints"):
            if d[k] is None:
                d[k] = []
        d["description"] = (d.get("description") or "").strip()
        d["path"] = str(d.get("path") or "")
        d["name"] = str(d.get("name") or "")
        return d

# ---------------- File scan ----------------

def find_nse_files(dirs: Sequence[str]) -> List[Path]:
    paths: List[Path] = []
    seen = set()
    for d in dirs:
        p = Path(d)
        if not p.is_dir():
            continue
        for f in p.rglob("*.nse"):
            try:
                rp = f.resolve()
            except Exception:
                rp = f
            if rp not in seen:
                seen.add(rp)
                paths.append(rp)
    return sorted(paths)

# ---------------- Parsing ----------------

TAG_LINE_RE = re.compile(r"^\s*--+\s*@(\w+)\s*:\s*(.+)$", re.IGNORECASE)  # -- @description: foo
DOC_LINE_RE = re.compile(r"^\s*---\s*(.+)$")  # --- NSEdoc comment line
CATEGORIES_LUA_RE = re.compile(r"categories\s*=\s*{([^}]*)}", re.IGNORECASE | re.DOTALL)
AUTHOR_LUA_RE = re.compile(r'author[s]?\s*=\s*(\{.*?\}|\[\[.*?\]\]|"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\')', re.IGNORECASE | re.DOTALL)
DESCRIPTION_LUA_RE = re.compile(
    r"description\s*=\s*(\[\[.*?\]\]|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*')",
    re.IGNORECASE | re.DOTALL,
)
HTML_TAG_RE = re.compile(r"<[^>]+>")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

RED = "\x1b[31m"
RESET = "\x1b[0m"

def _should_color(opt: str) -> bool:
    if opt == "always":
        return True
    if opt == "never":
        return False
    # auto
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def _compile_terms_regex(terms: List[str], *, case_sensitive: bool = False) -> Optional[re.Pattern]:
    terms = [t for t in (terms or []) if t]
    if not terms:
        return None
    # Dedup (case-insensitive) and sort longer first to avoid partial overshadow
    uniq = sorted(set(t.lower() for t in terms), key=lambda s: (-len(s), s))
    escaped = [re.escape(t) for t in uniq]
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

# Portrule hints
SHORTPORT_CALL_RE = re.compile(r"shortport\.(\w+)")
PORT_OR_SERVICE_RE = re.compile(r"shortport\.port_or_service\(([^)]*)\)", re.IGNORECASE | re.DOTALL)
PORTNUMBER_RE = re.compile(r"shortport\.portnumber\(([^)]*)\)", re.IGNORECASE | re.DOTALL)

def strip_html(s: str) -> str:
    return HTML_TAG_RE.sub("", s or "")

def parse_nse(path: Path) -> ScriptMeta:
    text = ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        pass

    description = ""
    authors: List[str] = []
    args: List[str] = []
    references: List[str] = []

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

    # 2b) author[s] = ... (Lua assignment parsing)
    am = AUTHOR_LUA_RE.search(text or "")
    if am:
        aval = am.group(1).strip()
        extracted = []
        if aval.startswith("{"):
            extracted = re.findall(r'["\\\']((?:\\.|[^"\\\'])+)["\\\']', aval)
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

    # 5) portrule hints (best-effort)
    service_hints: List[str] = []
    port_hints: List[int] = []

    # shortport.http / shortport.ssl / shortport.ftp / etc.
    for msp in SHORTPORT_CALL_RE.finditer(text or ""):
        func = msp.group(1).lower()
        if func not in ("port_or_service", "portnumber"):
            service_hints.append(func)

    def _extract_args_to_ports_services(argstr: str):
        services = re.findall(r'[\'"]([A-Za-z0-9_\-\.]+)[\'"]', argstr or "")
        nums = [int(n) for n in re.findall(r"\b\d{1,5}\b", argstr or "") if 0 < int(n) <= 65535]
        return services, nums

    for mpos in PORT_OR_SERVICE_RE.finditer(text or ""):
        s, n = _extract_args_to_ports_services(mpos.group(1))
        service_hints.extend(s)
        port_hints.extend(n)

    for mpn in PORTNUMBER_RE.finditer(text or ""):
        s, n = _extract_args_to_ports_services(mpn.group(1))
        port_hints.extend(n)
        port_hints.extend(n)

    # normalize
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
        updated_ts=updated_ts,
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

def ensure_index(update: bool, extra_dirs: Sequence[str]) -> Dict:
    idx = None if update else load_index()
    dirs = list(dict.fromkeys(env_nse_dirs() + DEFAULT_NSE_DIRS + list(extra_dirs)))
    if idx is None:
        idx = build_index(dirs)
        save_index(idx)

    scripts = idx.get("scripts", {})
    if scripts:
        total = len(scripts)
        empties = sum(1 for v in scripts.values() if not (v.get("description") or "").strip())
        if total > 0 and (empties / total) > 0.6:
            idx = build_index(dirs)
            save_index(idx)
    return idx

# ---------------- Search ----------------

def normalize(s: str) -> str:
    return (s or "").lower()

def matches(meta: Dict, query: str, regex: Optional[re.Pattern], exact: bool,
            category_filter: Optional[List[str]], author_filter: Optional[List[str]],
            *, name_only: bool = False, case_sensitive: bool = False) -> bool:
    if category_filter:
        mc = [normalize(x) for x in meta.get("categories", [])]
        if not any(normalize(c) in mc for c in category_filter):
            return False
    if author_filter:
        authors = normalize(", ".join(meta.get("authors", [])))
        if not any(normalize(a) in authors for a in author_filter):
            return False

    hay = meta.get("name","") if name_only else " ".join(filter(None, [
        meta.get("name",""),
        meta.get("description",""),
        " ".join(meta.get("categories",[])),
        " ".join(meta.get("authors",[])),
        " ".join(meta.get("args",[])),
        " ".join(meta.get("references",[])),
        meta.get("path",""),
    ]))

    if regex:
        try:
            return bool(regex.search(hay))
        except Exception:
            return False
    if query:
        if exact:
            # whole-word token AND match
            hay_use = hay if case_sensitive else hay.lower()
            tokens = set(re.findall(r"\b\w+\b", hay_use))
            q_tokens = re.findall(r"\b\w+\b", query)
            if not case_sensitive:
                q_tokens = [q.lower() for q in q_tokens]
            return all(q in tokens for q in q_tokens)
        # non-exact: AND of substrings
        terms = [t for t in re.split(r"\s+", query.strip()) if t]
        if case_sensitive:
            return all(t in hay for t in terms)
        else:
            low = hay.lower()
            return all(t.lower() in low for t in terms)
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
        # Strip ANSI/color before writing
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

def _distribute_widths(n_cols: int, max_width: int, mins: Optional[List[int]] = None, caps: Optional[List[int]] = None) -> List[int]:
    gaps = 2 * (n_cols - 1)
    usable = max(10 * n_cols, max_width - gaps)
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

def _wrap_plain(text: str, width: int) -> List[str]:
    import textwrap
    if width <= 0:
        return [text]
    text = text or ""
    return textwrap.wrap(text, width=width, replace_whitespace=False, drop_whitespace=False, break_long_words=True, break_on_hyphens=False) or [""]

def _render_table_generic(rows: List[List[str]], headers: List[str], max_width: int) -> str:
    n = len(headers)
    widths = _distribute_widths(n, max_width)
    def fmt_line(parts: List[str]) -> str:
        return "  ".join(ljust_visible(parts[i], widths[i]) for i in range(n))
    out: List[str] = []
    out.append(fmt_line(headers))
    out.append(fmt_line(["-"*w for w in widths]))
    for r in rows:
        wrapped_cols = [ _wrap_plain(r[i], widths[i]) for i in range(n) ]
        height = max(len(col) for col in wrapped_cols)
        for i in range(height):
            out.append(fmt_line([ wrapped_cols[c][i] if i < len(wrapped_cols[c]) else "" for c in range(n) ]))
    return "\n".join(out)

def _render_table_4col(rows: List[List[str]], headers: List[str], max_width: int, with_separators: bool = True) -> str:
    mins = [14, 14, 24, 20]
    caps = [32, 32, 9999, 60]
    widths = _distribute_widths(4, max_width, mins=mins, caps=caps)
    def fmt_line(parts: List[str]) -> str:
        return "  ".join(ljust_visible(parts[i], widths[i]) for i in range(4))
    out: List[str] = []
    out.append(fmt_line(headers))
    out.append(fmt_line(["-"*w for w in widths]))
    for r in rows:
        script, cats, desc, path = r[0], r[1], r[2], r[3]
        cols = [
            _wrap_plain(script, widths[0]),
            _wrap_plain(cats,   widths[1]),
            _wrap_plain(desc,   widths[2]),
            _wrap_plain(path,   widths[3]),
        ]
        height = max(len(c) for c in cols)
        for i in range(height):
            out.append(fmt_line([ cols[c][i] if i < len(cols[c]) else "" for c in range(4) ]))
        if with_separators:
            out.append(fmt_line(["-"*w for w in widths]))
    if with_separators and out and out[-1].strip().strip("-") == "":
        out.pop()
    return "\n".join(out)

def tabulate(rows: List[List[str]], headers: List[str], *, max_width: Optional[int] = None) -> str:
    if max_width is None:
        try:
            max_width = shutil.get_terminal_size(fallback=(120, 20)).columns
        except Exception:
            max_width = 120
    if len(headers) == 4:
        return _render_table_4col(rows, headers, max_width, with_separators=True)
    else:
        return _render_table_generic(rows, headers, max_width)

# -------- Structured output helpers --------

def _format_rows(rows: List[List[str]], headers: List[str], fmt: str) -> str:
    """Render rows into the requested format. Supported: table/json/yaml/ndjson/csv/tsv/xml"""
    fmt = (fmt or "table").lower()
    if fmt == "table":
        return tabulate(rows, headers=headers, max_width=None)

    # Build list of dicts for structured formats
    objs = [ { headers[i]: (row[i] if i < len(row) else "") for i in range(len(headers)) } for row in rows ]

    if fmt == "json":
        return json.dumps(objs, indent=2, ensure_ascii=False)

    if fmt == "ndjson":
        return "\n".join(json.dumps(o, ensure_ascii=False) for o in objs)

    if fmt in ("yaml", "yml"):
        # Minimal YAML emitter (no external deps)
        def to_yaml_obj(o, indent=0):
            sp = "  " * indent
            if isinstance(o, dict):
                lines = []
                for k, v in o.items():
                    if isinstance(v, (dict, list)):
                        lines.append(f"{sp}{k}:")
                        lines.append(to_yaml_obj(v, indent+1))
                    else:
                        vs = str(v)
                        if any(ch in vs for ch in [":","-","{","}","[","]","#","&","*","!",">","|","'",'"','%','@','`']):
                            vs = json.dumps(vs, ensure_ascii=False)
                        lines.append(f"{sp}{k}: {vs}")
                return "\n".join(lines)
            if isinstance(o, list):
                out = []
                for v in o:
                    if isinstance(v, (dict, list)):
                        out.append(f"{sp}-")
                        out.append(to_yaml_obj(v, indent+1))
                    else:
                        vs = str(v)
                        if any(ch in vs for ch in [":","-","{","}","[","]","#","&","*","!",">","|","'",'"','%','@','`']):
                            vs = json.dumps(vs, ensure_ascii=False)
                        out.append(f"{sp}- {vs}")
                return "\n".join(out)
            return f"{sp}{o}"
        return to_yaml_obj(objs)

    if fmt in ("csv","tsv"):
        import io, csv
        sep = "," if fmt == "csv" else "\t"
        sio = io.StringIO()
        w = csv.writer(sio, delimiter=sep)
        w.writerow(headers)
        for r in rows:
            w.writerow([r[i] if i < len(r) else "" for i in range(len(headers))])
        return sio.getvalue().rstrip("\n")

    if fmt == "xml":
        from xml.etree.ElementTree import Element, SubElement, tostring
        root = Element("results")
        for obj in objs:
            e = SubElement(root, "row")
            for k, v in obj.items():
                child = SubElement(e, k.replace(" ", "_").lower())
                child.text = str(v)
        try:
            return tostring(root, encoding="unicode")
        except Exception:
            return tostring(root, encoding="utf-8").decode("utf-8")

    # fallback to table
    return tabulate(rows, headers=headers, max_width=None)

def _format_paths(paths: List[str], fmt: str) -> str:
    fmt = (fmt or "table").lower()
    if fmt == "table":
        rows = [[p] for p in paths]
        return tabulate(rows, headers=["Path"], max_width=None)
    if fmt == "json":
        return json.dumps(paths, indent=2, ensure_ascii=False)
    if fmt == "ndjson":
        return "\n".join(json.dumps(p, ensure_ascii=False) for p in paths)
    if fmt in ("yaml","yml"):
        return "\n".join(f"- {p}" for p in paths)
    if fmt in ("csv","tsv"):
        import io, csv
        sep = "," if fmt == "csv" else "\t"
        sio = io.StringIO()
        w = csv.writer(sio, delimiter=sep)
        w.writerow(["Path"])
        for pth in paths:
            w.writerow([pth])
        return sio.getvalue().rstrip("\n")
    if fmt == "xml":
        from xml.etree.ElementTree import Element, SubElement, tostring
        root = Element("paths")
        for pth in paths:
            SubElement(root, "path").text = pth
        try:
            return tostring(root, encoding="unicode")
        except Exception:
            return tostring(root, encoding="utf-8").decode("utf-8")
    # fallback
    rows = [[p] for p in paths]
    return tabulate(rows, headers=["Path"], max_width=None)

# Service-to-port hints (non-exhaustive but practical)
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
}

def _name_service_hints(name: str) -> List[str]:
    pre = (name or "").split("-", 1)[0].lower()
    hints = []
    if pre in SERVICE_PORTS:
        hints.append(pre)
    if pre == "https":
        hints.extend(["https","ssl","http"])
    if pre.startswith("http"):
        hints.append("http")
    if pre.startswith("ssl") or pre.startswith("tls") or pre.startswith("https"):
        hints.extend(["ssl","tls","https"])
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
                a = int(a); b = int(b)
                if 0 < a <= 65535 and 0 < b <= 65535 and a <= b and (b - a) <= 10000:
                    result.update(range(a, b+1))
            except Exception:
                continue
        else:
            try:
                n = int(part)
                if 0 < n <= 65535:
                    result.add(n)
            except Exception:
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

def render_results(matches_list: List[Dict], paths_only: bool, *, max_width: Optional[int] = None,
                   color_opt: str = "auto", terms_regex: Optional[re.Pattern] = None, out_format: str = "table") -> str:
    out_format = (out_format or "table").lower()
    if paths_only:
        paths = [m["path"] for m in matches_list]
        return _format_paths(paths, out_format)

    rows = []
    for m in matches_list:
        name = m["name"]
        path = m["path"]
        cats = ",".join(m.get("categories", []) or []) or "-"
        desc = strip_html((m.get("description","") or "-").strip())
        rows.append([name, cats, desc, path])

    if out_format == "table":
        table = tabulate(rows, headers=["Script", "Categories", "Description", "Path"], max_width=max_width)
        table = highlight_text(table, terms_regex, _should_color(color_opt))
        return table
    else:
        return _format_rows(rows, ["Script", "Categories", "Description", "Path"], out_format)

def open_script(idx: Dict, name_or_path: str) -> Optional[Path]:
    if name_or_path.endswith(".nse") and Path(name_or_path).exists():
        return Path(name_or_path)
    meta = idx["scripts"].get(Path(name_or_path).stem)
    if meta:
        return Path(meta["path"])
    return None

def build_nmap_command(matches_list: List[Dict], target: str, script_args: Optional[str], ports: Optional[str]) -> str:
    names = ",".join(sorted(m["name"] for m in matches_list))
    parts = ["nmap"]
    if ports:
        parts += ["-p", ports]
    parts += ["--script", names]
    if script_args:
        parts += ["--script-args", script_args]
    parts.append(target)
    return " ".join(parts)

# ---------------- CLI ----------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(f"{BANNER}"
        "NSE Search is a fast, offline indexer & searcher for Nmap NSE scripts.\n"
        "Find scripts by name, description, category, author, args, or references;\n"
        "filter safely with exact/regex; colorize matches; export results in table, JSON,\n"
        "YAML, CSV/TSV, XML, or NDJSON; and generate ready-to-run nmap commands.\n\n"
        f"Made by: {AUTHOR}  |  Version: {__version__}  |  GitHub: {GITHUB}\n"),
        epilog=f"""Examples:
  # Rebuild the index (standalone) and print a summary
  {APP_NAME} --update

  # Simple search (AND over name/desc/categories/etc.)
  {APP_NAME} http wordpress

  # Regex search
  {APP_NAME} -r "(?i)ftpd.*backdoor"

  # Filter by category and author
  {APP_NAME} -c vuln -a "hdm"

  # List categories with descriptions and counts
  {APP_NAME} --list-categories

  # Show/copy a script by name
  {APP_NAME} --show http-title
  {APP_NAME} --copy http-title

  # Print an nmap command for matching scripts
  # (no terms defaults to '--script default')
  {APP_NAME} --run 8.8.8.8
  {APP_NAME} --run 8.8.8.8 --ports 80 -c vuln
  {APP_NAME} --run 8.8.8.8 http --ports 80 --script-args "useragent=MyUA,timeout=5s"

  # Paths-only output (useful for piping to editors/linters)
  {APP_NAME} -p http

  # Exact (word) match over names/descriptions/etc. (AND of words)
  {APP_NAME} -x "ftp brute"
  # Exact + name-only + case-sensitive
  {APP_NAME} -x --name-only --case-sensitive "ftp-anon"

  # Save output to a file (overwrite or append)
  {APP_NAME} http --out results.txt
  {APP_NAME} http --out results.txt --append

  # Disable colors
  {APP_NAME} --no-color http
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    p.add_argument("query", nargs="*", help="Search terms (AND). Leave empty to show help.")
    p.add_argument("-r", "--regex", help="Regex search across name/desc/cats/authors/args/refs.")
    p.add_argument("-x", "--exact", action="store_true", help="Exact word match for query terms")
    p.add_argument("-c", "--categories", help="Filter by categories (comma-separated)")
    p.add_argument("-a", "--authors", help="Filter by authors (comma-separated)")
    p.add_argument("-p", "--paths-only", action="store_true", help="Print only file paths")
    p.add_argument("-d", "--dirs", help="Additional directories to scan (OS-path-separated)")
    p.add_argument("-u", "--update", action="store_true", help="Rebuild the index now")
    p.add_argument("--show", help="Show a script's contents (by name or path)")
    p.add_argument("--copy", help="Copy a script to the current directory (by name or path)")
    p.add_argument("--list-categories", action="store_true", help="List all categories with descriptions and counts")
    p.add_argument("--run", metavar="TARGET", help="Print an nmap command to run matching scripts against TARGET")
    p.add_argument("--script-args", help="Arguments to pass to --script-args when using --run")
    p.add_argument("--ports", help="Ports for nmap -p when using --run (e.g., 80,443 or 1-1024)")
    p.add_argument("--max-width", type=int, help="Maximum table width (default: terminal width)")
    p.add_argument("--format", choices=["table","json","yaml","ndjson","csv","tsv","xml"], default="table", help="Select output format")
    p.add_argument("--color", choices=["auto","always","never"], default="auto", help="Colorize matches in output (default: auto)")
    p.add_argument("--no-color", action="store_true", help="Disable colored output (alias for --color=never)")
    p.add_argument("--out", metavar="FILE", help="Write output to FILE instead of stdout")
    p.add_argument("--append", action="store_true", help="Append to FILE when used with --out (default: overwrite)")
    p.add_argument("--quiet", action="store_true", help="Suppress status messages (e.g., write confirmation)")
    p.add_argument("--name-only", action="store_true", help="Limit matching to script names only")
    p.add_argument("--case-sensitive", action="store_true", help="Make matching case-sensitive (affects -x and normal search)")
    p.add_argument("--version", action="version", version=f"%(prog)s v{VERSION}")

    args = p.parse_args(argv)

    # Normalize output format & color
    out_format = getattr(args, "format", "table").lower() if getattr(args, "format", None) else "table"
    if getattr(args, "no_color", False):
        args.color = "never"
    elif args.color == "auto" and os.environ.get("NO_COLOR"):
        args.color = "never"

    # If --update is the only action, rebuild now and exit with a summary
    only_update = args.update and not any([
        args.query, args.regex, args.categories, args.authors, args.run,
        args.list_categories, args.show, args.copy, args.paths_only
    ])
    if only_update:
        extra_dirs: List[str] = []
        if args.dirs:
            extra_dirs = [d for d in args.dirs.split(os.pathsep) if d.strip()]
        idx = ensure_index(update=True, extra_dirs=extra_dirs)
        scripts = idx.get("scripts", {})
        dirs = idx.get("_dirs", [])
        print(f"[+] Index rebuilt: {len(scripts)} scripts indexed from {len(dirs)} dir(s).")
        print(f"[+] Cache: {INDEX_PATH}")
        return 0

    # Help on empty input (and not requesting other actions)
    if not any([args.query, args.regex, args.categories, args.authors, args.run, args.list_categories, args.show, args.copy, args.paths_only]):
        p.print_help()
        return 0

    extra_dirs: List[str] = []
    if args.dirs:
        extra_dirs = [d for d in args.dirs.split(os.pathsep) if d.strip()]

    idx = ensure_index(update=args.update, extra_dirs=extra_dirs)

    if args.show:
        path = open_script(idx, args.show)
        if not path or not path.exists():
            print(f"[!] Could not find script: {args.show}", file=sys.stderr)
            return 1
        content = path.read_text(encoding="utf-8", errors="ignore")
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
        print(f"[+] Copied to {dst}")
        return 0

    scripts: Dict[str, Dict] = idx["scripts"]

    if args.list_categories:
        counts: Dict[str, int] = {}
        for m in scripts.values():
            for c in m.get("categories", []) or []:
                counts[c] = counts.get(c, 0) + 1
        all_cats = sorted(set(counts.keys()) | set(CATEGORIES_INFO.keys()))
        rows = []
        for c in all_cats:
            rows.append([c, CATEGORIES_INFO.get(c, "-"), str(counts.get(c, 0))])

        if out_format == "table":
            t = tabulate(rows, headers=["Category", "Description", "Count"], max_width=args.max_width)
            query_terms = []
            if args.categories:
                query_terms += [t.strip() for t in args.categories.split(",") if t.strip()]
            terms_re = _compile_terms_regex(query_terms, case_sensitive=args.case_sensitive)
            t = highlight_text(t, terms_re, _should_color(args.color))
            write_output(t, args.out, args.append, args.quiet)
        else:
            text = _format_rows(rows, ["Category", "Description", "Count"], out_format)
            write_output(text, args.out, args.append, args.quiet)
        return 0

    query_text = " ".join(args.query).strip()
    regex = None
    if args.regex:
        try:
            regex = re.compile(args.regex, re.IGNORECASE)
        except re.error as e:
            print(f"[!] Bad regex: {e}", file=sys.stderr)
            return 2

    category_filter = [s.strip().lower() for s in args.categories.split(",")] if args.categories else None
    author_filter = [s.strip().lower() for s in args.authors.split(",")] if args.authors else None

    # If --run is used with no query/regex/categories/authors, default to category 'default'
    default_run_no_terms = False
    if args.run and not any([args.query, args.regex, args.categories, args.authors]):
        category_filter = ["default"]
        default_run_no_terms = True
        print("[i] No search terms or filters provided for --run; defaulting to category 'default'. Use --categories to override.", file=sys.stderr)

    matches_list = []
    for meta in scripts.values():
        if matches(meta, query_text, regex, args.exact, category_filter, author_filter, name_only=args.name_only, case_sensitive=args.case_sensitive):
            matches_list.append(meta)

    def rank(m: Dict) -> Tuple[int, str]:
        hay_name = m["name"]
        hay_desc = m.get("description", "")
        if not args.case_sensitive:
            hay_name_cmp = hay_name.lower()
            hay_desc_cmp = hay_desc.lower()
            q = query_text.lower()
        else:
            hay_name_cmp = hay_name
            hay_desc_cmp = hay_desc
            q = query_text
        primary = 0
        if q:
            if hay_name_cmp.find(q) != -1:
                primary = -2
            elif not args.name_only and hay_desc_cmp.find(q) != -1:
                primary = -1
        return (primary, hay_name.lower())

    matches_list.sort(key=rank)

    if args.run:
        if default_run_no_terms:
            parts = ["nmap"]
            if args.ports:
                parts += ["-p", args.ports]
            parts += ["--script", "default"]
            if args.script_args:
                parts += ["--script-args", args.script_args]
            parts.append(args.run)
            cmd = " ".join(parts)
            write_output(cmd, args.out, args.append, args.quiet)
            return 0
        if not matches_list:
            print("[!] No matching scripts to run.", file=sys.stderr)
            return 1
        user_ports = _parse_ports_arg(args.ports) if args.ports else None
        if user_ports:
            narrowed = [m for m in matches_list if _script_matches_ports(m, user_ports)]
            if narrowed:
                matches_list = narrowed
        cmd = build_nmap_command(matches_list, args.run, args.script_args, args.ports)
        write_output(cmd, args.out, args.append, args.quiet)
        return 0

    # Build regex for highlighting from query terms and also include category/author filters
    query_terms = re.findall(r"\S+", query_text) if query_text else []
    if args.categories:
        query_terms += [t.strip() for t in args.categories.split(",") if t.strip()]
    if args.authors:
        query_terms += [t.strip() for t in args.authors.split(",") if t.strip()]
    terms_re = _compile_terms_regex(query_terms, case_sensitive=args.case_sensitive)

    out_text = render_results(matches_list, paths_only=args.paths_only, max_width=args.max_width,
                              color_opt=args.color, terms_regex=terms_re, out_format=out_format)
    write_output(out_text, args.out, args.append, args.quiet)
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
