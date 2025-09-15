# NSE Search

```
 __    __   ______   ________   ______                                           __       
|  \  |  \ /      \ |        \ /      \                                         |  \      
| $$\ | $$|  $$$$$$\| $$$$$$$$|  $$$$$$\  ______    ______    ______    _______ | $$____  
| $$$\| $$| $$___\$$| $$__    | $$___\$$ /      \  |      \  /      \  /       \| $$    \ 
| $$$$\ $$ \$$    \ | $$  \    \$$    \ |  $$$$$$\  \$$$$$$\|  $$$$$$\|  $$$$$$$| $$$$$$$\
| $$\$$ $$ _\$$$$$$\| $$$$$    _\$$$$$$\| $$    $$ /      $$| $$   \$$| $$      | $$  | $$
| $$ \$$$$|  \__| $$| $$_____ |  \__| $$| $$$$$$$$|  $$$$$$$| $$      | $$_____ | $$  | $$
| $$  \$$$ \$$    $$| $$     \ \$$    $$ \$$     \ \$$    $$| $$       \$$     \| $$  | $$
 \$$   \$$  \$$$$$$  \$$$$$$$$  \$$$$$$   \$$$$$$$  \$$$$$$$ \$$        \$$$$$$$ \$$   \$$
 ```


**NSE Search** is a fast offline indexer & searcher for Nmap NSE scripts. It crawls your local `nmap/scripts/` directories, caches metadata, and lets you search by name, description, category, author, and more—with clean tables, colored highlights, structured output formats, and one-shot `nmap --script` generation.

**Made by:** Tony Hayden • **Version:** v1.0.1 • **GitHub:** <http://github.com/haydena23>

---

## Features

- 🔎 Search over **name / description / categories / authors / args / references**
- 🎯 Filters: `--regex`, `--exact`, `--name-only`, `--case-sensitive`, `--categories`, `--authors`
- 🎨 Pretty **table** output with optional color highlighting
- 🧰 Structured outputs: **JSON / YAML / CSV / TSV / XML / NDJSON** via `--format`
- 🚀 Generate ready-to-run `nmap --script` commands with `--run` (plus `--ports`, `--script-args`)
- 🗂️ Discover categories with `--list-categories`
- 📜 `--show`/`--copy` to view or copy script sources
- ⚡ Caching at `~/.cache/nsesearch/index.json`; force rebuild with `--update`

> Tip: extend scan paths using `NSE_PATH` (OS-path-separated) or `--dirs`.

---

## Requirements

- **Python 3.8+**
- **Nmap** installed so its `scripts/` directory exists
  - Debian/Ubuntu: `sudo apt install nmap`
  - macOS (Homebrew): `brew install nmap`
  - Windows: WSL recommended (install via your distro)

No third-party Python packages required.


## Installation
### Option A: pipx (Recommended)
```bash
pipx install git+https://github.com/haydena23/nsesearch.git
nsesearch -h
```

### Option B: Quick run (no install)
```bash
git clone https://github.com/haydena23/nsesearch.git
cd nsesearch
python3 nsesearch.py -h
```

### Option C: pip (User Install)
```bash
pip install --user git+https://github.com/haydena23/nsesearch.git
~/.local/bin/nsesearch -h   # ensure this is on your PATH
```

## Usage
```
usage: nsesearch.py [-h] [-r REGEX] [-x] [-c CATEGORIES] [-a AUTHORS] [-p] [-d DIRS] [-u]
                    [--show SHOW] [--copy COPY] [--list-categories] [--run TARGET]
                    [--script-args SCRIPT_ARGS] [--ports PORTS] [--max-width MAX_WIDTH]
                    [--format {table,json,yaml,ndjson,csv,tsv,xml}]
                    [--color {auto,always,never}] [--no-color] [--out FILE] [--append] [--quiet]
                    [--name-only] [--case-sensitive] [--version]
                    [query ...]

positional arguments:
  query                 Search terms (AND). Leave empty to show help.

options:
  -h, --help            show this help message and exit
  -r, --regex REGEX     Regex search across name/desc/cats/authors/args/refs.
  -x, --exact           Exact word match for query terms
  -c, --categories CATEGORIES
                        Filter by categories (comma-separated)
  -a, --authors AUTHORS
                        Filter by authors (comma-separated)
  -p, --paths-only      Print only file paths
  -d, --dirs DIRS       Additional directories to scan (OS-path-separated)
  -u, --update          Rebuild the index now
  --show SHOW           Show a script's contents (by name or path)
  --copy COPY           Copy a script to the current directory (by name or path)
  --list-categories     List all categories with descriptions and counts
  --run TARGET          Print an nmap command to run matching scripts against TARGET
  --script-args SCRIPT_ARGS
                        Arguments to pass to --script-args when using --run
  --ports PORTS         Ports for nmap -p when using --run (e.g., 80,443 or 1-1024)
  --max-width MAX_WIDTH
                        Maximum table width (default: terminal width)
  --format {table,json,yaml,ndjson,csv,tsv,xml}
                        Select output format (default: table)
  --color {auto,always,never}
                        Colorize matches in output (default: auto)
  --no-color            Disable colored output (alias for --color=never)
  --out FILE            Write output to FILE instead of stdout
  --append              Append to FILE when used with --out (default: overwrite)
  --quiet               Suppress status messages (e.g., write confirmation)
  --name-only           Limit matching to script names only
  --case-sensitive      Make matching case-sensitive (affects -x and normal search)
  --version             Show program’s version number and exit

Examples:
  # Rebuild the index (standalone) and print a summary
  nsesearch.py --update

  # Simple search (AND over name/desc/categories/etc.)
  nsesearch.py http wordpress

  # Regex search
  nsesearch.py -r "(?i)ftpd.*backdoor"

  # Filter by category and author
  nsesearch.py -c vuln -a "hdm"

  # List categories with descriptions and counts
  nsesearch.py --list-categories

  # Show/copy a script by name
  nsesearch.py --show http-title
  nsesearch.py --copy http-title

  # Print an nmap command for matching scripts
  # (no terms defaults to '--script default')
  nsesearch.py --run 8.8.8.8
  nsesearch.py --run 8.8.8.8 --ports 80 -c vuln
  nsesearch.py --run 8.8.8.8 http --ports 80 --script-args "useragent=MyUA,timeout=5s"

  # Paths-only output (useful for piping to editors/linters)
  nsesearch.py -p http

  # Exact (word) match over names/descriptions/etc. (AND of words)
  nsesearch.py -x "ftp brute"
  # Exact + name-only + case-sensitive
  nsesearch.py -x --name-only --case-sensitive "ftp-anon"

  # Save output to a file (overwrite or append)
  nsesearch.py http --out results.txt
  nsesearch.py http --out results.txt --append

  # Structured formats
  nsesearch.py http --format json
  nsesearch.py http --format yaml --out results.yaml --quiet
  nsesearch.py http --format csv
  nsesearch.py http --format tsv
  nsesearch.py http --format xml
  nsesearch.py http --format ndjson

  # Disable colors
  nsesearch.py --no-color http

```