# WebIDA - Experimental PE File Viewer (Browser-Based) 

This tool allows you to view the headers of a PE file in the browser. It is a work in progress and is not intended for production use. It is a proof of concept to show that it is possible to view the headers of a PE file in the browser. 

## Features 

- AI Assistant
- View PE Headers (MS-DOS Header, COFF Header, Optional Header, Data Directories)
- View Disassembly
- View Hex Viewer
- View Sections

## Expected Features 

- Working AI Assistant
- Working dissasmbler viewer (with modified version of [IndAlok/r2web](https://github.com/IndAlok/r2web))

## Tech Stack

- HTML
- CSS
- JavaScript
- TypeScript 
- Python

## Dependencies 

- [requests] Python requst library
- [fastapi] Python backend
- [pelib_JS](https://github.com/TIMOTHY1498/pelib_js_client_TEST) Modified version of pe-library for JS to use in client side.

## Working Test Binaries (Parser)

- FL64.exe, FLEngine_x64.dll - FL Studio 25 Executable
- sample_malw.exe, testbin.exe - A sample malware (download at your own risk)
- Vanguard.sys - Valorant's Anti-Cheat
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

This tool is licensed under the MIT License. See `LICENSE` for more information.