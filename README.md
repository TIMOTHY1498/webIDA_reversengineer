![Logo](https://github.com/TIMOTHY1498/webIDA_reversengineer/blob/main/icon_med.png)

# WebIDA - Experimental PE Decompiler & Parser (Browser-Based) 

This tool allows you to decompile and view the headers of a PE file in the browser. It is a work in progress and is not intended for production use.

# DISCLAIMER (for binaries)
The `testbins` directory contains types of binaries (INCLUDING REAL MALWARE). **DO NOT EXECUTE any of these binaries**, because some of these files may contain real malware or other potentially harmful code.

The binaries are provided **solely for research, testing, and educational purposes**. I, the developer of this project **does not endorse, distribute, or encourage the use of any malicious software** contained within the directory.

## Features 

- AI Assistant
- View PE Headers (MS-DOS Header, COFF Header, Optional Header, Data Directories)
- Hex Viewer (Read-only)
- View Sections
- Working dissasmbler viewer (Powered with [IndAlok/rzwasi](https://github.com/IndAlok/rzwasi))

## Expected Features 

- Working AI Assistant

## Tech Stack

- HTML
- CSS
- JavaScript
- TypeScript 
- Python

## Dependencies 

- [groq] Python Groq AI library
- [fastapi] Python backend
- [pelib_JS](https://github.com/TIMOTHY1498/pelib_js_client_TEST) Modified version of pe-library for JS to use in client side.
- [rzwasi](https://github.com/IndAlok/rzwasi) Rizin WASM Version for doing client-side dissambely
- [dotenv] Python .env loader

## Working Test Binaries (Parser)

- FL64.exe, FLEngine_x64.dll - FL Studio Executable & Library
- sample_malw.exe, testbin.exe, infostealer_INFECTED.exe - A sample malware (download at your own risk)
- Vanguard.sys - Valorant's Kernel-Level Anti-Cheat
- ChromeSetup.exe - Google Chrome Installer
- cmd.exe (WINE) - Windows Command Prompt (WINE's version)
- regedit.exe (WINE) - Windows Registry Editor (WINE's version)
- notepad.exe (WINE) - Windows Notepad (WINE's version)

## Not Working Test Binaries (Parser)

- NGService.exe - Blue Archive's Anti-Cheat (Returned failed promise)
```
Promise {<rejected>: Error: After Resource section, sections except for relocation are not supported
    at NtExecutable.js}

"After Resource section, sections except for relocation are not supported"
```

## License

This tool is licensed under the MIT License.
