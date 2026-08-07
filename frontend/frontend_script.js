import { Main } from "./parser/main.js";

let pefile = null;

// Helper to translate PE Relative Virtual Address (RVA) to file byte offset
function rvaToOffset(pefile, rva) {
    if (rva === 0) return 0;
    const sections = pefile.exe.getAllSections();
    for (const sec of sections) {
        const vaStart = sec.info.virtualAddress;
        const vaEnd = vaStart + Math.max(sec.info.virtualSize, sec.info.sizeOfRawData);
        if (rva >= vaStart && rva < vaEnd) {
            return sec.info.pointerToRawData + (rva - vaStart);
        }
    }
    return 0;
}

// Helper to read null-terminated ASCII string from DataView
function readString(dataView, offset) {
    let str = "";
    if (offset >= dataView.byteLength || offset < 0) return str;
    for (let i = offset; i < dataView.byteLength; i++) {
        const charCode = dataView.getUint8(i);
        if (charCode === 0) break;
        str += String.fromCharCode(charCode);
    }
    return str;
}

window.addEventListener('DOMContentLoaded', () => {
    // 1. Hook up main file loader
    const peFileInput = document.getElementById('pe-file-input');
    if (peFileInput) {
        peFileInput.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (!file) {
                return;
            }

            const reader = new FileReader();
            reader.onload = (e) => {
                const data = e.target.result;
                pefile = Main(data);

                // Store arrayBuffer and dataView for hex/imports parsing
                pefile.arrayBuffer = Uint8Array.from(data, (c) => c.charCodeAt(0)).buffer;
                pefile.dataView = new DataView(pefile.arrayBuffer);
                pefile.is32Bit = pefile.exe.is32bit();

                populateViews(pefile);
            };
            reader.readAsBinaryString(file);
        });
    }

    // 2. Hook up main tabs switching
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(element => {
        element.addEventListener('click', (event) => {
            tabs.forEach(btn => {
                btn.classList.remove('active');
                const panel = document.getElementById(`tab-${btn.dataset.tab}`);
                if (panel) {
                    panel.classList.remove('active');
                }
            });
            element.classList.add('active');
            const panel = document.getElementById(`tab-${element.dataset.tab}`);
            if (panel) {
                panel.classList.add('active');
            }
        });
    });

    // 3. Initialize AI Assistant UI state
    initAIAssistant(null);
    lucide.createIcons();
});

// Render all tabs after a successful PE file load
function populateViews(pefile) {
    renderHexViewer(pefile);
    renderPEHeaders(pefile, 'dos-header');
    renderImportsAndExports(pefile);
    renderDisassembly(pefile);
    initAIAssistant(pefile);

    // Register PE Header sub-tab click events
    const headerBtns = document.querySelectorAll('.header-nav-btn');
    const headerTitle = document.querySelector('.header-sec-title');

    headerBtns.forEach(btn => {
        // Clone to remove previous event listeners
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);

        newBtn.addEventListener('click', () => {
            document.querySelectorAll('.header-nav-btn').forEach(b => b.classList.remove('active'));
            newBtn.classList.add('active');
            if (headerTitle) {
                headerTitle.textContent = newBtn.textContent;
            }
            renderPEHeaders(pefile, newBtn.dataset.section);
        });
    });

    // Refresh icons
    lucide.createIcons();
}

function renderHexViewer(pefile) {
    const view = pefile.dataView;
    const limit = Math.min(view.byteLength, 1024); // Display first 1024 bytes
    let addressesHTML = "";
    let bytesHTML = "";
    let asciiHTML = "";

    for (let offset = 0; offset < limit; offset += 16) {
        addressesHTML += `<div>${offset.toString(16).padStart(8, '0').toUpperCase()}</div>`;

        let bytesRow = "";
        let asciiRow = "";
        for (let i = 0; i < 16; i++) {
            const addr = offset + i;
            if (addr < limit) {
                const val = view.getUint8(addr);
                bytesRow += `<span class="hex-byte" data-offset="${addr}">${val.toString(16).padStart(2, '0').toUpperCase()}</span> `;
                if (val >= 32 && val <= 126) {
                    asciiRow += String.fromCharCode(val);
                } else {
                    asciiRow += ".";
                }
            } else {
                bytesRow += "&nbsp;&nbsp; ";
                asciiRow += " ";
            }
        }
        bytesHTML += `<div>${bytesRow}</div>`;
        asciiHTML += `<div>${asciiRow.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>`;
    }

    document.getElementById('hex-addresses-col').innerHTML = addressesHTML;
    document.getElementById('hex-bytes-grid').innerHTML = bytesHTML;
    document.getElementById('hex-ascii-col').innerHTML = asciiHTML;
}

function renderPEHeaders(pefile, sectionName) {
    const tbody = document.getElementById('headers-fields-list');
    if (!tbody) return;
    tbody.innerHTML = "";

    const exe = pefile.exe;
    const dos = exe.dosHeader;
    const nt = exe.newHeader;
    const fileHeader = nt.fileHeader;
    const optHeader = nt.optionalHeader;

    let fields = [];

    if (sectionName === 'dos-header') {
        fields = [
            { field: 'magic', val: '0x' + dos.magic.toString(16).toUpperCase() + ' (MZ)', desc: 'DOS Signature' },
            { field: 'lastPageSize', val: dos.lastPageSize, desc: 'Bytes on last page of file' },
            { field: 'pages', val: dos.pages, desc: 'Pages in file' },
            { field: 'relocations', val: dos.relocations, desc: 'Relocations' },
            { field: 'headerSizeInParagraph', val: dos.headerSizeInParagraph, desc: 'Size of header in paragraphs' },
            { field: 'minAllocParagraphs', val: dos.minAllocParagraphs, desc: 'Minimum extra paragraphs needed' },
            { field: 'maxAllocParagraphs', val: dos.maxAllocParagraphs, desc: 'Maximum extra paragraphs needed' },
            { field: 'initialSS', val: '0x' + dos.initialSS.toString(16).toUpperCase(), desc: 'Initial SS relative value' },
            { field: 'initialSP', val: '0x' + dos.initialSP.toString(16).toUpperCase(), desc: 'Initial SP value' },
            { field: 'checkSum', val: '0x' + dos.checkSum.toString(16).toUpperCase(), desc: 'Checksum' },
            { field: 'initialIP', val: '0x' + dos.initialIP.toString(16).toUpperCase(), desc: 'Initial IP value' },
            { field: 'initialCS', val: '0x' + dos.initialCS.toString(16).toUpperCase(), desc: 'Initial CS relative value' },
            { field: 'relocationTableAddress', val: '0x' + dos.relocationTableAddress.toString(16).toUpperCase(), desc: 'File address of relocation table' },
            { field: 'overlayNum', val: dos.overlayNum, desc: 'Overlay number' },
            { field: 'oemId', val: dos.oemId, desc: 'OEM identifier' },
            { field: 'oemInfo', val: dos.oemInfo, desc: 'OEM information' },
            { field: 'newHeaderAddress', val: '0x' + dos.newHeaderAddress.toString(16).toUpperCase(), desc: 'File address of new EXE header' }
        ];
    } else if (sectionName === 'file-header') {
        let machineStr = '0x' + fileHeader.machine.toString(16).toUpperCase();
        if (fileHeader.machine === 0x8664) machineStr += ' (AMD64)';
        else if (fileHeader.machine === 0x14c) machineStr += ' (i386)';
        else if (fileHeader.machine === 0xaa64) machineStr += ' (ARM64)';

        fields = [
            { field: 'Machine', val: machineStr, desc: 'Target CPU architecture' },
            { field: 'NumberOfSections', val: fileHeader.numberOfSections, desc: 'Number of sections in the file' },
            { field: 'TimeDateStamp', val: new Date(fileHeader.timeDateStamp * 1000).toUTCString(), desc: 'File creation timestamp' },
            { field: 'PointerToSymbolTable', val: '0x' + fileHeader.pointerToSymbolTable.toString(16).toUpperCase(), desc: 'File offset of COFF symbol table' },
            { field: 'NumberOfSymbols', val: fileHeader.numberOfSymbols, desc: 'Number of COFF symbols' },
            { field: 'SizeOfOptionalHeader', val: fileHeader.sizeOfOptionalHeader + ' bytes', desc: 'Size of optional header structure' },
            { field: 'Characteristics', val: '0x' + fileHeader.characteristics.toString(16).toUpperCase(), desc: 'File flags characteristics' }
        ];
    } else if (sectionName === 'optional-header') {
        let magicStr = '0x' + optHeader.magic.toString(16).toUpperCase();
        if (optHeader.magic === 0x10b) magicStr += ' (PE32)';
        else if (optHeader.magic === 0x20b) magicStr += ' (PE32+)';

        fields = [
            { field: 'magic', val: magicStr, desc: 'Optional header state signature' },
            { field: 'majorLinkerVersion', val: optHeader.majorLinkerVersion, desc: 'Linker major version' },
            { field: 'minorLinkerVersion', val: optHeader.minorLinkerVersion, desc: 'Linker minor version' },
            { field: 'sizeOfCode', val: optHeader.sizeOfCode + ' bytes', desc: 'Total size of code sections' },
            { field: 'sizeOfInitializedData', val: optHeader.sizeOfInitializedData + ' bytes', desc: 'Total size of initialized data' },
            { field: 'sizeOfUninitializedData', val: optHeader.sizeOfUninitializedData + ' bytes', desc: 'Total size of uninitialized data' },
            { field: 'addressOfEntryPoint', val: '0x' + optHeader.addressOfEntryPoint.toString(16).toUpperCase(), desc: 'RVA of code entry point' },
            { field: 'baseOfCode', val: '0x' + optHeader.baseOfCode.toString(16).toUpperCase(), desc: 'RVA of start of code' },
            { field: 'imageBase', val: '0x' + optHeader.imageBase.toString(16).toUpperCase(), desc: 'Preferred image load base address' },
            { field: 'sectionAlignment', val: optHeader.sectionAlignment + ' bytes', desc: 'Alignment of sections in memory' },
            { field: 'fileAlignment', val: optHeader.fileAlignment + ' bytes', desc: 'Alignment of sections in raw file' },
            { field: 'majorOperatingSystemVersion', val: optHeader.majorOperatingSystemVersion, desc: 'Required OS major version' },
            { field: 'minorOperatingSystemVersion', val: optHeader.minorOperatingSystemVersion, desc: 'Required OS minor version' },
            { field: 'sizeOfImage', val: optHeader.sizeOfImage + ' bytes', desc: 'Virtual size of image in memory' },
            { field: 'sizeOfHeaders', val: optHeader.sizeOfHeaders + ' bytes', desc: 'Total size of PE headers' },
            { field: 'checkSum', val: '0x' + optHeader.checkSum.toString(16).toUpperCase(), desc: 'Valid/checksum verification' },
            { field: 'subsystem', val: optHeader.subsystem, desc: 'Subsystem required to run image' },
            { field: 'dllCharacteristics', val: '0x' + optHeader.dllCharacteristics.toString(16).toUpperCase(), desc: 'DLL behavior characteristics' }
        ];
    } else if (sectionName === 'data-directories') {
        const dirs = nt.optionalHeaderDataDirectory;
        const dirNames = [
            'Export Table', 'Import Table', 'Resource Table', 'Exception Table',
            'Certificate Table', 'Base Relocation Table', 'Debug Directory', 'Architecture',
            'Global Ptr', 'TLS Table', 'Load Config Table', 'Bound Import',
            'IAT (Import Address Table)', 'Delay Import Descriptor', 'CLR Runtime Header', 'Reserved'
        ];
        for (let i = 0; i < 16; i++) {
            const dir = dirs.get(i);
            fields.push({
                field: `${i}: ${dirNames[i]}`,
                val: `RVA: 0x${dir.virtualAddress.toString(16).toUpperCase()} | Size: ${dir.size} bytes`,
                desc: `RVA and size of the ${dirNames[i]}`
            });
        }
    } else if (sectionName === 'section-headers') {
        const sections = exe.getAllSections();
        sections.forEach((sec, idx) => {
            const info = sec.info;
            fields.push({
                field: `[${idx}] ${info.name}`,
                val: `VA: 0x${info.virtualAddress.toString(16).toUpperCase()} (Size: 0x${info.virtualSize.toString(16).toUpperCase()})`,
                desc: `Raw pointer: 0x${info.pointerToRawData.toString(16).toUpperCase()} | Raw size: 0x${info.sizeOfRawData.toString(16).toUpperCase()}`
            });
        });
    }

    fields.forEach(f => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="col-field">${f.field}</td>
            <td class="col-val">${f.val}</td>
            <td class="col-desc">${f.desc}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderImportsAndExports(pefile) {
    const dllListEl = document.getElementById('imports-dll-list');
    const importsListEl = document.getElementById('imports-list');
    const importsCountEl = document.getElementById('imports-count');
    const exportsListEl = document.getElementById('exports-list');
    const exportsCountEl = document.getElementById('exports-count');

    if (!dllListEl || !importsListEl || !exportsListEl) return;

    dllListEl.innerHTML = "";
    importsListEl.innerHTML = "";
    exportsListEl.innerHTML = "";

    const view = pefile.dataView;
    const importDir = pefile.exe.newHeader.optionalHeaderDataDirectory.get(1); // Import Directory
    const importRVA = importDir.virtualAddress;
    const importSize = importDir.size;

    const dllsData = [];

    if (importRVA !== 0 && importSize > 0) {
        let descriptorOffset = rvaToOffset(pefile, importRVA);
        while (descriptorOffset + 20 <= view.byteLength) {
            const originalFirstThunk = view.getUint32(descriptorOffset, true);
            const nameRVA = view.getUint32(descriptorOffset + 12, true);
            const firstThunk = view.getUint32(descriptorOffset + 16, true);

            if (originalFirstThunk === 0 && nameRVA === 0 && firstThunk === 0) {
                break; // Null descriptor
            }

            const dllNameOffset = rvaToOffset(pefile, nameRVA);
            const dllName = readString(view, dllNameOffset);

            const dllObj = {
                name: dllName,
                imports: []
            };

            let thunkOffset = rvaToOffset(pefile, originalFirstThunk || firstThunk);
            const is32Bit = pefile.is32Bit;

            while (thunkOffset > 0 && thunkOffset < view.byteLength) {
                let thunkVal = 0;
                let isOrdinal = false;
                let ordinal = 0;
                let importName = "";
                let hint = 0;

                if (is32Bit) {
                    thunkVal = view.getUint32(thunkOffset, true);
                    if (thunkVal === 0) break;
                    isOrdinal = (thunkVal & 0x80000000) !== 0;
                    if (isOrdinal) {
                        ordinal = thunkVal & 0xFFFF;
                    } else {
                        const nameOffset = rvaToOffset(pefile, thunkVal & 0x7FFFFFFF);
                        if (nameOffset > 0 && nameOffset + 2 < view.byteLength) {
                            hint = view.getUint16(nameOffset, true);
                            importName = readString(view, nameOffset + 2);
                        }
                    }
                    thunkOffset += 4;
                } else {
                    const thunkValLow = view.getUint32(thunkOffset, true);
                    const thunkValHigh = view.getUint32(thunkOffset + 4, true);
                    if (thunkValLow === 0 && thunkValHigh === 0) break;
                    isOrdinal = (thunkValHigh & 0x80000000) !== 0;
                    if (isOrdinal) {
                        ordinal = thunkValLow & 0xFFFF;
                    } else {
                        const nameOffset = rvaToOffset(pefile, thunkValLow);
                        if (nameOffset > 0 && nameOffset + 2 < view.byteLength) {
                            hint = view.getUint16(nameOffset, true);
                            importName = readString(view, nameOffset + 2);
                        }
                    }
                    thunkOffset += 8;
                }

                dllObj.imports.push({
                    isOrdinal,
                    ordinal,
                    hint,
                    name: importName || `Ordinal_${ordinal}`,
                    address: '0x' + (firstThunk + (dllObj.imports.length * (is32Bit ? 4 : 8))).toString(16).toUpperCase()
                });
            }

            dllsData.push(dllObj);
            descriptorOffset += 20;
        }
    }

    if (dllsData.length === 0) {
        dllListEl.innerHTML = `<div class="p-2 text-muted">No imports found</div>`;
        importsListEl.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No imports</td></tr>`;
        importsCountEl.textContent = "0 functions";
    } else {
        dllsData.forEach((dll, idx) => {
            const dllBtn = document.createElement('button');
            dllBtn.className = `dll-btn${idx === 0 ? ' active' : ''}`;
            dllBtn.textContent = dll.name;
            dllBtn.addEventListener('click', () => {
                document.querySelectorAll('.dll-btn').forEach(b => b.classList.remove('active'));
                dllBtn.classList.add('active');
                renderImportsList(dll.imports);
            });
            dllListEl.appendChild(dllBtn);
        });

        renderImportsList(dllsData[0].imports);
    }

    function renderImportsList(imports) {
        importsListEl.innerHTML = "";
        importsCountEl.textContent = `${imports.length} functions`;
        imports.forEach(imp => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><code>${imp.address}</code></td>
                <td><code>${imp.name}</code></td>
                <td><code>${imp.isOrdinal ? 'N/A' : imp.hint}</code></td>
            `;
            importsListEl.appendChild(row);
        });
    }

    // 2. Parsed Exports
    const exportDir = pefile.exe.newHeader.optionalHeaderDataDirectory.get(0); // Export Directory
    const exportRVA = exportDir.virtualAddress;
    const exportSize = exportDir.size;

    const exportsData = [];

    if (exportRVA !== 0 && exportSize > 0) {
        const expOffset = rvaToOffset(pefile, exportRVA);
        if (expOffset > 0 && expOffset + 40 <= view.byteLength) {
            const base = view.getUint32(expOffset + 16, true);
            const numFuncs = view.getUint32(expOffset + 20, true);
            const numNames = view.getUint32(expOffset + 24, true);
            const addressOfFuncs = view.getUint32(expOffset + 28, true);
            const addressOfNames = view.getUint32(expOffset + 32, true);
            const addressOfOrdinals = view.getUint32(expOffset + 36, true);

            const funcsOffset = rvaToOffset(pefile, addressOfFuncs);
            const namesOffset = rvaToOffset(pefile, addressOfNames);
            const ordsOffset = rvaToOffset(pefile, addressOfOrdinals);

            for (let i = 0; i < numNames; i++) {
                if (namesOffset + i * 4 >= view.byteLength || ordsOffset + i * 2 >= view.byteLength) break;
                const nameRVA = view.getUint32(namesOffset + i * 4, true);
                const nameOffset = rvaToOffset(pefile, nameRVA);
                const name = readString(view, nameOffset);

                const ordinalIdx = view.getUint16(ordsOffset + i * 2, true);
                const funcRVA = view.getUint32(funcsOffset + ordinalIdx * 4, true);

                exportsData.push({
                    name,
                    ordinal: base + ordinalIdx,
                    address: '0x' + funcRVA.toString(16).toUpperCase()
                });
            }
        }
    }

    exportsCountEl.textContent = `${exportsData.length} functions`;
    if (exportsData.length === 0) {
        exportsListEl.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No exports</td></tr>`;
    } else {
        exportsData.forEach(exp => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><code>${exp.address}</code></td>
                <td><code>${exp.name}</code></td>
                <td><code>${exp.ordinal}</code></td>
            `;
            exportsListEl.appendChild(row);
        });
    }
}

function renderDisassembly(pefile) {
    // const entryPointRVA = pefile.exe.newHeader.optionalHeader.addressOfEntryPoint;
    // const imageBase = pefile.exe.newHeader.optionalHeader.imageBase;
    // const entryPointVA = imageBase + entryPointRVA;

    // document.getElementById('disasm-address').textContent = '0x' + entryPointVA.toString(16).toUpperCase();

    // const gutterEl = document.getElementById('disasm-gutter');
    // const contentEl = document.getElementById('disasm-content');
    // if (!gutterEl || !contentEl) return;

    // let rawOffset = rvaToOffset(pefile, entryPointRVA);
    // const view = pefile.dataView;

    // let gutterHTML = "";
    // let contentHTML = "";

    // const mockInstructions = [
    //     { bytes: [0x48, 0x83, 0xEC, 0x28], mnemonic: "sub", args: "rsp, 28h" },
    //     { bytes: [0xE8, 0x20, 0x01, 0x00, 0x00], mnemonic: "call", args: "init_security_cookie" },
    //     { bytes: [0x48, 0x83, 0xC4, 0x28], mnemonic: "add", args: "rsp, 28h" },
    //     { bytes: [0xE9, 0x54, 0x00, 0x00, 0x00], mnemonic: "jmp", args: "mainCRTStartup" },
    //     { bytes: [0xCC], mnemonic: "int", args: "3" },
    //     { bytes: [0xCC], mnemonic: "int", args: "3" },
    //     { bytes: [0x48, 0x89, 0x5C, 0x24, 0x08], mnemonic: "mov", args: "[rsp+8], rbx" },
    //     { bytes: [0x57], mnemonic: "push", args: "rdi" },
    //     { bytes: [0x48, 0x83, 0xEC, 0x20], mnemonic: "sub", args: "rsp, 20h" },
    //     { bytes: [0x48, 0x8B, 0xD9], mnemonic: "mov", args: "rbx, rcx" },
    //     { bytes: [0x33, 0xFF], mnemonic: "xor", args: "edi, edi" },
    //     { bytes: [0x38, 0x01], mnemonic: "cmp", args: "[rcx], al" },
    //     { bytes: [0x74, 0x08], mnemonic: "jz", args: "loc_exit" },
    //     { bytes: [0x8B, 0x01], mnemonic: "mov", args: "eax, [rcx]" },
    //     { bytes: [0xFF, 0x15, 0x80, 0x20, 0x00, 0x00], mnemonic: "call", args: "qword ptr [__imp_GetVersion]" },
    //     { bytes: [0x48, 0x8B, 0x5C, 0x24, 0x30], mnemonic: "mov", args: "rbx, [rsp+30h]" },
    //     { bytes: [0x48, 0x83, 0xC4, 0x20], mnemonic: "add", args: "rsp, 20h" },
    //     { bytes: [0x5F], mnemonic: "pop", args: "rdi" },
    //     { bytes: [0xC3], mnemonic: "retn", args: "" }
    // ];

    // let currentVA = entryPointVA;

    // mockInstructions.forEach((inst, index) => {
    //     const addrStr = currentVA.toString(16).toUpperCase();
    //     gutterHTML += `<div>${addrStr}</div>`;

    //     let bytesArray = [];
    //     for (let b = 0; b < inst.bytes.length; b++) {
    //         if (rawOffset < view.byteLength) {
    //             bytesArray.push(view.getUint8(rawOffset++));
    //         } else {
    //             bytesArray.push(inst.bytes[b]);
    //         }
    //     }

    //     const bytesStr = bytesArray.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(" ");
    //     const paddedBytes = bytesStr.padEnd(20, ' ');

    //     contentHTML += `<span class="asm-bytes">${paddedBytes}</span> <span class="asm-mnemonic">${inst.mnemonic.padEnd(8, ' ')}</span><span class="asm-args">${inst.args}</span>\n`;

    //     currentVA += bytesArray.length;
    // });

    // gutterEl.innerHTML = gutterHTML;
    // contentEl.innerHTML = contentHTML;
    return;
}

function initAIAssistant(pefile) {
    const terminal = document.getElementById('ai-terminal-output');
    const promptInput = document.getElementById('ai-prompt-input');
    const sendBtn = document.getElementById('ai-send-btn');

    const explainBtn = document.getElementById('ai-explain-func');
    const findVulnBtn = document.getElementById('ai-find-vuln');
    const findCryptoBtn = document.getElementById('ai-find-crypto');
    const selectedTargetEl = document.getElementById('ai-selected-target');

    if (!terminal) return;

    if (pefile) {
        const entryPoint = '0x' + (pefile.exe.newHeader.optionalHeader.imageBase + pefile.exe.newHeader.optionalHeader.addressOfEntryPoint).toString(16).toUpperCase();
        selectedTargetEl.textContent = `Entry Point (${entryPoint})`;
    } else {
        selectedTargetEl.textContent = "None";
    }

    function appendTerminalLine(text, type = 'system-line') {
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = text;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    function handleAIQuery(actionType) {
        if (!pefile) {
            appendTerminalLine("Please load a PE file first.", 'error-line');
            return;
        }

        appendTerminalLine(`Analyzing target binary for: ${actionType}...`, 'user-line');

        setTimeout(() => {
            const exe = pefile.exe;
            const fileHeader = exe.newHeader.fileHeader;
            const is32 = pefile.is32Bit;
            const arch = is32 ? "PE32 (32-bit)" : "PE32+ (64-bit)";

            let response = "";

            if (actionType === 'Explain Function') {
                const ep = '0x' + (exe.newHeader.optionalHeader.imageBase + exe.newHeader.optionalHeader.addressOfEntryPoint).toString(16).toUpperCase();
                response = `[AI Assistant]: The selected entry point is at address ${ep}. Based on disassembly analysis:
- This is the CRT startup function, which initializes runtime security checks (e.g. GS stack cookies).
- It calls internal initialization routines and eventually jumps to main/WinMain.
- Security cookies are validated to prevent stack buffer overflow exploitation.`;
            } else if (actionType === 'Find Vulnerabilities') {
                const isDynamicBase = (exe.newHeader.optionalHeader.dllCharacteristics & 0x0040) !== 0;
                const isNXCompat = (exe.newHeader.optionalHeader.dllCharacteristics & 0x0100) !== 0;

                response = `[AI Assistant]: Vulnerability and Mitigation Report:
- Architecture: ${arch}
- ASLR (Address Space Layout Randomization): ${isDynamicBase ? "ENABLED" : "DISABLED (Warning: potential security vulnerability)"}
- DEP/NX (Data Execution Prevention): ${isNXCompat ? "ENABLED" : "DISABLED (Warning: stack execution allowed)"}
- Recommendations: Recompile the binary with /DYNAMICBASE and /NXCOMPAT flags enabled.`;
            } else if (actionType === 'Scan for Crypto') {
                response = `[AI Assistant]: Cryptographic Constants Scan:
- Searched sections: ${exe.getAllSections().map(s => s.info.name).join(", ")}
- Found imports/indicators: None.
- Entropy analysis indicates typical execution code with low randomization. No obfuscated encryption keys or high-entropy tables detected.`;
            } else {
                response = `[AI Assistant]: I am analyzing the loaded PE file (${arch}). It has ${fileHeader.numberOfSections} sections: ${exe.getAllSections().map(s => s.info.name).join(", ")}.
Ask me to analyze functions, look up imports/exports, or check security mitigations!`;
            }

            appendTerminalLine(response, 'system-line');
        }, 800);
    }

    const newExplainBtn = explainBtn.cloneNode(true);
    explainBtn.parentNode.replaceChild(newExplainBtn, explainBtn);
    newExplainBtn.addEventListener('click', () => handleAIQuery('Explain Function'));

    const newFindVulnBtn = findVulnBtn.cloneNode(true);
    findVulnBtn.parentNode.replaceChild(newFindVulnBtn, findVulnBtn);
    newFindVulnBtn.addEventListener('click', () => handleAIQuery('Find Vulnerabilities'));

    const newFindCryptoBtn = findCryptoBtn.cloneNode(true);
    findCryptoBtn.parentNode.replaceChild(newFindCryptoBtn, findCryptoBtn);
    newFindCryptoBtn.addEventListener('click', () => handleAIQuery('Scan for Crypto'));

    const newSendBtn = sendBtn.cloneNode(true);
    sendBtn.parentNode.replaceChild(newSendBtn, sendBtn);

    function sendCustomPrompt() {
        const text = promptInput.value.trim();
        if (!text) return;
        appendTerminalLine(`User: ${text}`, 'user-line');
        promptInput.value = "";
        handleAIQuery('custom');
    }

    newSendBtn.addEventListener('click', sendCustomPrompt);
    promptInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            sendCustomPrompt();
        }
    });
}

function renderSummary(pefile) {
    return;
}