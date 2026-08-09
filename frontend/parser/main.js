import * as Format from './index_format.js';
import NtExecutable from './NtExecutable.js';
import NtExecutableResource from './NtExecutableResource.js';
import { calculateCheckSumForPE } from './functions.js';
import * as Type from './index_type.js';

function convertBinaryString(bin_str) {
  return Uint8Array.from(bin_str, (c) => c.charCodeAt(0)).buffer;
}

function readUtf16String(view, offset) {
  let chars = [];
  for (let i = offset; ; i += 2) {
    const code = view.getUint16(i, true);
    if (code === 0) break;
    chars.push(String.fromCharCode(code));
  }
  return chars.join("");
}

function align4(offset) {
  return (offset + 3) & ~3;
}

function parseStringTable(view, offset, limit) {
  let result = {};
  let pos = offset;

  while (pos < limit) {
    const wLength = view.getUint16(pos, true);
    const wValueLength = view.getUint16(pos + 2, true);
    const wType = view.getUint16(pos + 4, true);
    const key = readUtf16String(view, pos + 6);

    let valuePos = align4(pos + 6 + (key.length + 1) * 2);
    let endPos = pos + wLength;

    if (wValueLength > 0) {
      const value = readUtf16String(view, valuePos);
      result[key] = value;
    }

    pos = align4(endPos);
  }
  return result;
}

function parseVersionInfo(view) {
  const length = view.getUint16(0, true);
  const valueLength = view.getUint16(2, true);
  const type = view.getUint16(4, true);
  const key = readUtf16String(view, 6);

  let pos = align4(6 + (key.length + 1) * 2);
  pos = align4(pos + valueLength); // Skip VS_FIXEDFILEINFO

  const result = {};

  while (pos < length) {
    const childLength = view.getUint16(pos, true);
    const childValueLength = view.getUint16(pos + 2, true);
    const childType = view.getUint16(pos + 4, true);
    const childKey = readUtf16String(view, pos + 6);
    let childPos = align4(pos + 6 + (childKey.length + 1) * 2);

    if (childKey === "StringFileInfo") {
      let stPos = childPos;
      while (stPos < pos + childLength) {
        const stLength = view.getUint16(stPos, true);
        const stKey = readUtf16String(view, stPos + 6);
        const stValuePos = align4(stPos + 6 + (stKey.length + 1) * 2);
        const table = parseStringTable(view, stValuePos, stPos + stLength);
        Object.assign(result, table);
        stPos = align4(stPos + stLength);
      }
    }

    pos = align4(pos + childLength);
  }

  return result;
}

async function findMetaData(exe, exe_res) {
  try {
    let exe_version_info = exe_res.entries.find(x => x.type == 16);
    return parseVersionInfo(new DataView(exe_version_info.bin));
  } catch (error) {
    console.warn("[error] Failed to find metadata:", error);
    return null;
  }
}

async function loadPEFIle(arr_buff) {
  let exe = NtExecutable.from(arr_buff);
  let exe_res = NtExecutableResource.from(exe);

  let is32Bit = exe.is32bit();
  let mdta = await findMetaData(exe, exe_res);

  if (mdta) {
    return {
      exe: exe,
      exe_metadata: mdta,
      exe_res: exe_res,
      is32Bit: is32Bit,
      checksum: calculateCheckSumForPE(arr_buff),
    };
  } else {
    return {
      exe: exe,
      exe_res: exe_res,
      is32Bit: is32Bit,
      checksum: calculateCheckSumForPE(arr_buff),
    };
  }
}

export function Main(bin_PE) {
  let arr_buff = convertBinaryString(bin_PE);
  let loaded_PE = loadPEFIle(arr_buff);

  console.log("[info] PE file loaded successfully");
  console.log(loaded_PE);
  return loaded_PE;
}