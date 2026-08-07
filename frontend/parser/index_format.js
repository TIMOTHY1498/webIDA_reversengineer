import ArrayFormatBase from './ArrayFormatBase.js';
import FormatBase from './FormatBase.js';
import ImageDataDirectoryArray, {} from './ImageDataDirectoryArray.js';
import ImageDirectoryEntry from './ImageDirectoryEntry.js';
import ImageDosHeader from './ImageDosHeader.js';
import ImageFileHeader from './ImageFileHeader.js';
import ImageNtHeaders from './ImageNtHeaders.js';
import ImageOptionalHeader from './ImageOptionalHeader.js';
import ImageOptionalHeader64 from './ImageOptionalHeader64.js';
import ImageSectionHeaderArray, {} from './ImageSectionHeaderArray.js';
export { ArrayFormatBase, FormatBase, ImageDataDirectoryArray, ImageDirectoryEntry, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader, ImageOptionalHeader64, ImageSectionHeaderArray, };
export function getImageDosHeader(bin) {
    return ImageDosHeader.from(bin);
}
export function getImageNtHeadersByDosHeader(bin, dosHeader) {
    return ImageNtHeaders.from(bin, dosHeader.newHeaderAddress);
}
export function getImageSectionHeadersByNtHeaders(bin, dosHeader, ntHeaders) {
    return ImageSectionHeaderArray.from(bin, ntHeaders.fileHeader.numberOfSections, dosHeader.newHeaderAddress + ntHeaders.byteLength);
}
export function findImageSectionBlockByDirectoryEntry(bin, dosHeader, ntHeaders, entryType) {
    const arr = ImageSectionHeaderArray.from(bin, ntHeaders.fileHeader.numberOfSections, dosHeader.newHeaderAddress + ntHeaders.byteLength);
    const len = arr.length;
    const rva = ntHeaders.optionalHeaderDataDirectory.get(entryType).virtualAddress;
    for (let i = 0; i < len; ++i) {
        const sec = arr.get(i);
        const vaEnd = sec.virtualAddress + sec.virtualSize;
        if (rva >= sec.virtualAddress && rva < vaEnd) {
            const ptr = sec.pointerToRawData;
            if (!ptr) {
                return null;
            }
            return bin.slice(ptr, ptr + sec.sizeOfRawData);
        }
        if (rva < sec.virtualAddress) {
            return null;
        }
    }
    return null;
}
//# sourceMappingURL=index_format.js.map