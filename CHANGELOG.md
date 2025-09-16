# **v1.0.2**

This update focuses on adding powerful new features for script analysis, improving search capabilities, enhancing output formatting, and increasing overall robustness and user experience.

#### ✨ **New Features**

*   **Advanced Search with OR Logic**: The search query now supports `OR` operators, allowing for more complex and flexible searches (e.g., `"http brute OR smb brute"`).
*   **Exclusion Filters**: You can now exclude specific categories and authors from your search results using the new `--exclude-categories` and `--exclude-authors` flags.
*   **Service and Port Filtering**: Added `--service` and `--port` filters to find scripts relevant to specific network services or port numbers.
*   **Dependency Analysis**: The script now parses and indexes script dependencies (`require` statements). You can view these with the new `--deps` flag.
*   **Script Diffing**: A `--diff` command has been added to compare two NSE scripts (by name or path) and view a colorized, unified diff directly in your terminal.
*   **Direct Nmap Execution**: In addition to generating a command with `--run`, you can now execute it directly using the `--exec` flag.
*   **Lua Syntax Highlighting**: The `--show` command now features full Lua syntax highlighting for improved readability.
*   **Configuration File Support**: The script now looks for a configuration file at `~/.config/nsesearchrc.json` to load default script directories and output formats.
*   **Sorting Options**: You can now sort search results by name, last update time, or category using the `--sort-by` flag.

####  Improvements

*   **More Robust Indexing**:
    *   The index now stores a hash of each script's content to detect changes more reliably.
    *   Added a timeout to the file search to prevent hangs on unusually large or problematic directories.
    *   The index will automatically rebuild if the script directories have changed since the last build.
*   **Enhanced Output Formatting**:
    *   Table rendering is now more adaptive to different terminal widths, improving readability on both wide and narrow screens.
    *   Structured formats (JSON, YAML, etc.) now support optional color highlighting when the `--color=always` flag is used.
    *   Improved HTML parsing to preserve content within `<code>` tags as backticks.
*   **Improved User Experience**:
    *   The command-line interface now has mutually exclusive groups for actions like `--update`, `--show`, `--run`, etc., making it clearer and less error-prone.
    *   Running the script with no arguments now displays a helpful usage tip instead of the full help menu.
    *   Added more detailed warnings for invalid port ranges or misuse of command-line arguments.
*   **Code and Dependency Updates**:
    *   The script now uses `shlex.join` for safer command string construction.
    *   Dependencies like `difflib` and `subprocess` have been added to support the new diffing and execution features.
    *   Internal data models have been updated to include script dependencies and content hashes.

#### 🐞 **Bug Fixes**

*   Corrected an issue where the author parsing logic could fail on complex, nested Lua tables.
*   Improved the accuracy of service and port hint extraction from `shortport.service()` calls.
*   Ensured consistent handling of file paths and encodings, especially on different operating systems.
*   Fixed a command injection vulnerability when `build_nmap_command` constructs a list of arguments, not sanitizing input before passing to `subprocess.run`

***