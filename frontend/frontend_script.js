import { Main } from "./parser/main.js";
// the "./diassm/rizin.js" script SHOULD already initilized in the webpage. ("index.html"). see line 312.

let pefile = null;
let rizinRuntimePromise = null;
let rizin_session = null;
let loaded_pe_functions = [];
let selected_pe_function = null;

let AI_TESTSERVER_LOCAL = "http://127.0.0.1:8000/chatwithAI"; // for local testing

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

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

async function ensureRizinRuntime() {
    if (rizinRuntimePromise) {
        return rizinRuntimePromise;
    }

    rizinRuntimePromise = new Promise((resolve) => {
        const runtime = globalThis.Module || {};
        if (runtime._rzweb_create_session) {
            resolve(runtime);
            return;
        }

        const previous = runtime.onRuntimeInitialized;
        runtime.onRuntimeInitialized = () => {
            if (typeof previous === 'function') {
                previous();
            }
            resolve(runtime);
        };
    });

    return rizinRuntimePromise;
}

function allocateCString(runtime, text) {
    const bytes = new TextEncoder().encode(String(text) + '\0');
    const ptr = runtime._malloc?.(bytes.length);
    if (!ptr) {
        return 0;
    }

    const heap = new Uint8Array(runtime.HEAPU8.buffer, ptr, bytes.length);
    heap.set(bytes);
    return ptr;
}

function freeCString(runtime, ptr) {
    if (ptr && typeof runtime._free === 'function') {
        runtime._free(ptr);
    }
}

window.addEventListener('DOMContentLoaded', () => {
    const peFileInput = document.getElementById('pe-file-input');
    if (peFileInput) {
        peFileInput.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (!file) {
                return;
            }
            const loadingOverlay = document.getElementById('loading-overlay');
            if (loadingOverlay) {
                loadingOverlay.classList.remove('hidden');
            }

            const reader = new FileReader();
            reader.onload = async (e) => {
                const data = e.target.result;

                await new Promise(resolve => setTimeout(resolve, 50));

                try {
                    let pefile = await Main(data);

                    selected_pe_function = null;
                    pefile.fileName = file.name;
                    pefile.arrayBuffer = Uint8Array.from(data, (c) => c.charCodeAt(0)).buffer;
                    pefile.dataView = new DataView(pefile.arrayBuffer);

                    // Update Toolbar File Details
                    const toolbarFilename = document.getElementById('toolbar-filename');
                    if (toolbarFilename) toolbarFilename.textContent = file.name;

                    const toolbarFiletype = document.getElementById('toolbar-filetype');
                    if (toolbarFiletype) {
                        toolbarFiletype.textContent = pefile.is32Bit ? "PE32 (32-bit)" : "PE32+ (64-bit)";
                    }

                    // do rizin stuff here

                    document.getElementById('functions-list').innerHTML = '';

                    let createSession = Module.cwrap('rzweb_create_session', 'number', []);
                    if (!rizin_session) {
                        rizin_session = createSession();
                    }
                    // Write binary data as Uint8Array to prevent encoding corruption
                    Module.FS.writeFile('/sample.bin', new Uint8Array(pefile.arrayBuffer));
                    let openFile = Module.cwrap('rzweb_open_file', 'number', ['number', 'string']);
                    openFile(rizin_session, '/sample.bin');

                    // Properly wrap rzweb_cmd to marshal string inputs and outputs
                    let rzweb_cmd = Module.cwrap('rzweb_cmd', 'string', ['number', 'string']);
                    
                    // Run analysis to discover functions in the PE
                    rzweb_cmd(rizin_session, "aa");

                    let afljResult = rzweb_cmd(rizin_session, "aflj");
                    loaded_pe_functions = afljResult ? JSON.parse(afljResult) : [];
                    console.log(loaded_pe_functions);

                    for (const func of loaded_pe_functions) {
                        const funcButton = document.createElement('button');
                        funcButton.className = 'btnfunc';
                        funcButton.textContent = `${func.name} @ 0x${func.offset.toString(16).toUpperCase()}`;
                        funcButton.addEventListener('click', () => {
                            selected_pe_function = func;
                            const selectedTarget = document.getElementById('ai-selected-target');
                            if (selectedTarget) {
                                selectedTarget.textContent = `${func.name} (0x${func.offset.toString(16).toUpperCase()})`;
                            }
                            const disasmResult = rzweb_cmd(rizin_session, `pdf @ ${func.offset}`);
                            renderDisassembly(disasmResult);
                        });
                        document.getElementById('functions-list').appendChild(funcButton);
                    }

                    document.getElementById('functions-count').textContent = `${loaded_pe_functions.length}`;
                    const entryPoint = '0x' + (pefile.exe.newHeader.optionalHeader.imageBase + pefile.exe.newHeader.optionalHeader.addressOfEntryPoint).toString(16).toUpperCase();
                    document.getElementById('toolbar-entrypoint').textContent = entryPoint;

                    populateViews(pefile);
                } catch (err) {
                    console.error("Error parsing PE file:", err);
                    alert("Error parsing PE file: " + err.message);
                } finally {
                    if (loadingOverlay) {
                        loadingOverlay.classList.add('hidden');
                    }
                }
            };
            reader.readAsBinaryString(file);
        });
    }

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

    const resetButton = document.getElementById('reset-button');
    if (resetButton) {
        resetButton.addEventListener('click', () => {
            window.location.reload();
        });
    }

    const globalSearch = document.getElementById('global-search');
    if (globalSearch) {
        globalSearch.addEventListener('input', (e) => {
            const query = e.target.value;
            const funcSearch = document.getElementById('functions-search');
            if (funcSearch) {
                funcSearch.value = query;
                funcSearch.dispatchEvent(new Event('input'));
            }
        });
    }

    initAIAssistant(null);
    lucide.createIcons();
});

async function populateViews(pefile) {
    renderHexViewer(pefile);
    renderPEHeaders(pefile, 'dos-header');
    renderImportsAndExports(pefile);
    renderSummary(pefile);
    // await renderDisassembly(pefile);
    // renderSectionBand(pefile);
    // renderFunctionsList(pefile);
    initAIAssistant(pefile);

    const headerBtns = document.querySelectorAll('.header-nav-btn');
    const headerTitle = document.querySelector('.header-sec-title');

    headerBtns.forEach(btn => {
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

    lucide.createIcons();
}

// Shitty vibecoded frontend render functions :)

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

async function renderDisassembly(asmText) {
    const gutterEl = document.getElementById('disasm-gutter');
    const contentEl = document.getElementById('disasm-content');

    try {
        console.log("[info] successfully dissassembled the binary using Rizin.");
    } catch (err) {
        console.error('[err] Rizin disassembly failed:', err);
    }

    // if (!asmText.trim()) {
    //     asmText = 'Rizin disassembly is not available yet. \nThe frontend is ready to display the returned assembly output once the wasm bridge responds.';
    // }

    const lines = asmText.split(/\r?\n/);
    gutterEl.innerHTML = lines.map((_, index) => `<div>${index + 1}</div>`).join('');
    contentEl.textContent = lines.join('\n');
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

    function getParsedMetadata() {
        if (!pefile?.exe) return null;

        const fileHeader = pefile.exe.newHeader.fileHeader;
        const optionalHeader = pefile.exe.newHeader.optionalHeader;
        return {
            fileName: pefile.fileName,
            fileSize: pefile.dataView?.byteLength,
            architecture: pefile.is32Bit ? "PE32 (32-bit)" : "PE32+ (64-bit)",
            machine: fileHeader.machine,
            numberOfSections: fileHeader.numberOfSections,
            timestamp: fileHeader.timeDateStamp,
            imageBase: optionalHeader.imageBase,
            entryPointRva: optionalHeader.addressOfEntryPoint,
            sections: pefile.exe.getAllSections().map(section => section.info)
        };
    }

    async function handleAIQuery(actionType, prompt = '') {
        // if (pefile == null) {
        //     appendTerminalLine("Please load a PE file first.", 'error-line');
        //     return;
        // }

        // appendTerminalLine(`User: ${prompt || actionType}`, 'user-line');

        // appendTerminalLine(`Analyzing target binary for: ${actionType}...`, 'user-line');
        // if (!pefile) return null;
        // if (!selected_pe_function && actionType !== 'custom') {
        //     appendTerminalLine("Please select a function from the functions list first.", 'error-line');
        //     return;
        // }

        const request = {
            message: prompt || actionType,
            action: actionType,
            selected_function: selected_pe_function,
            metadata: getParsedMetadata()
        };

        try {
            const response = await fetch(AI_TESTSERVER_LOCAL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(request)
            });
            
            const responseText = await response.text();
            let responseBody;
            try {
                responseBody = JSON.parse(responseText);
            } catch {
                responseBody = responseText;
            }
            if (!response.ok) {
                throw new Error(typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody));
            }
            appendTerminalLine(`[AI Assistant]: ${typeof responseBody === 'string' ? responseBody : responseBody.response ?? JSON.stringify(responseBody)}`, 'system-line');
        } catch (error) {
            appendTerminalLine(`AI request failed: ${error.message}`, 'error-line');
        }
    }

    const newExplainBtn = explainBtn.cloneNode(true);
    explainBtn.parentNode.replaceChild(newExplainBtn, explainBtn);
    newExplainBtn.addEventListener('click', () => handleAIQuery('Explain Function'));

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
        handleAIQuery('custom', text);
    }

    newSendBtn.addEventListener('click', sendCustomPrompt);
    promptInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            sendCustomPrompt();
        }
    });
}

function renderSummary(pefile) {
    const summaryContent = document.querySelector('#tab-summary .summary-content');
    if (!summaryContent || !pefile) return;

    const exe = pefile.exe;
    const dos = exe.dosHeader;
    const nt = exe.newHeader;
    const fileHeader = nt.fileHeader;
    const optHeader = nt.optionalHeader;
    const sections = exe.getAllSections();

    let machineStr = 'Unknown';
    if (fileHeader.machine === 0x8664) machineStr = 'AMD64 (x86-64)';
    else if (fileHeader.machine === 0x14c) machineStr = 'i386 (x86)';
    else if (fileHeader.machine === 0xaa64) machineStr = 'ARM64';

    const fileSize = pefile.dataView.byteLength;
    const timestamp = new Date(fileHeader.timeDateStamp * 1000).toUTCString();
    const entryPoint = '0x' + (optHeader.imageBase + optHeader.addressOfEntryPoint).toString(16).toUpperCase();
    
    summaryContent.innerHTML = `
        <div class="summary-grid">
            <div class="summary-section">
                <h3>File Information</h3>
                <table class="summary-table">
                    <tr>
                        <td class="label">Filename:</td>
                        <td class="value"><code>${escapeHtml(pefile.fileName)}</code></td>
                    </tr>
                    <tr>
                        <td class="label">File Size:</td>
                        <td class="value">${(fileSize / 1024).toFixed(2)} KB</td>
                    </tr>
                    <tr>
                        <td class="label">Format:</td>
                        <td class="value">${pefile.is32Bit ? 'PE32 (32-bit)' : 'PE32+ (64-bit)'}</td>
                    </tr>
                    <tr>
                        <td class="label">Machine:</td>
                        <td class="value">${machineStr}</td>
                    </tr>
                    <tr>
                        <td class="label">Timestamp:</td>
                        <td class="value">${timestamp}</td>
                    </tr>
                </table>
            </div>

            <div class="summary-section">
                <h3>Memory Layout</h3>
                <table class="summary-table">
                    <tr>
                        <td class="label">Image Base:</td>
                        <td class="value"><code>0x${optHeader.imageBase.toString(16).toUpperCase()}</code></td>
                    </tr>
                    <tr>
                        <td class="label">Entry Point (RVA):</td>
                        <td class="value"><code>0x${optHeader.addressOfEntryPoint.toString(16).toUpperCase()}</code></td>
                    </tr>
                    <tr>
                        <td class="label">Entry Point (VA):</td>
                        <td class="value"><code>${entryPoint}</code></td>
                    </tr>
                    <tr>
                        <td class="label">Image Size:</td>
                        <td class="value">${(optHeader.sizeOfImage / 1024).toFixed(2)} KB</td>
                    </tr>
                    <tr>
                        <td class="label">Section Alignment:</td>
                        <td class="value">0x${optHeader.sectionAlignment.toString(16).toUpperCase()}</td>
                    </tr>
                </table>
            </div>

            <div class="summary-section">
                <h3>Statistics</h3>
                <table class="summary-table">
                    <tr>
                        <td class="label">Sections:</td>
                        <td class="value">${fileHeader.numberOfSections}</td>
                    </tr>
                    <tr>
                        <td class="label">Functions:</td>
                        <td class="value">${loaded_pe_functions.length}</td>
                    </tr>
                    <tr>
                        <td class="label">Linker Version:</td>
                        <td class="value">${optHeader.majorLinkerVersion}.${optHeader.minorLinkerVersion}</td>
                    </tr>
                    <tr>
                        <td class="label">Subsystem:</td>
                        <td class="value">${optHeader.subsystem === 3 ? 'Windows CUI' : optHeader.subsystem === 2 ? 'Windows GUI' : optHeader.subsystem}</td>
                    </tr>
                </table>
            </div>

            <div class="summary-section">
                <h3>Sections</h3>
                <table class="summary-table">
                    ${sections.map(sec => `
                        <tr>
                            <td class="label"><code>${sec.info.name}</code></td>
                            <td class="value">
                                VA: 0x${sec.info.virtualAddress.toString(16).toUpperCase()} 
                                | Size: 0x${sec.info.virtualSize.toString(16).toUpperCase()}
                            </td>
                        </tr>
                    `).join('')}
                </table>
            </div>
        </div>
    `;
}