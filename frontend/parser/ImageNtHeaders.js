import { createDataView } from './functions.js';
import FormatBase from './FormatBase.js';
import ImageDataDirectoryArray from './ImageDataDirectoryArray.js';
import ImageFileHeader from './ImageFileHeader.js';
import ImageOptionalHeader from './ImageOptionalHeader.js';
import ImageOptionalHeader64 from './ImageOptionalHeader64.js';
export default class ImageNtHeaders extends FormatBase {
    static DEFAULT_SIGNATURE = 0x4550; // 'PE\x00\x00'
    constructor(view) {
        super(view);
    }
    static from(bin, offset = 0) {
        const magic = createDataView(bin, offset + ImageFileHeader.size, 6).getUint16(4, true);
        let len = 4 + ImageFileHeader.size + ImageDataDirectoryArray.size;
        if (magic === ImageOptionalHeader64.DEFAULT_MAGIC) {
            len += ImageOptionalHeader64.size;
        }
        else {
            len += ImageOptionalHeader.size;
        }
        return new ImageNtHeaders(createDataView(bin, offset, len));
    }
    isValid() {
        return this.signature === ImageNtHeaders.DEFAULT_SIGNATURE;
    }
    is32bit() {
        return (this.view.getUint16(ImageFileHeader.size + 4, true) ===
            ImageOptionalHeader.DEFAULT_MAGIC);
    }
    get signature() {
        return this.view.getUint32(0, true);
    }
    set signature(val) {
        this.view.setUint32(0, val, true);
    }
    get fileHeader() {
        return ImageFileHeader.from(this.view.buffer, this.view.byteOffset + 4);
    }
    get optionalHeader() {
        const off = ImageFileHeader.size + 4;
        const magic = this.view.getUint16(off, true);
        if (magic === ImageOptionalHeader64.DEFAULT_MAGIC) {
            return ImageOptionalHeader64.from(this.view.buffer, this.view.byteOffset + off);
        }
        else {
            return ImageOptionalHeader.from(this.view.buffer, this.view.byteOffset + off);
        }
    }
    get optionalHeaderDataDirectory() {
        return ImageDataDirectoryArray.from(this.view.buffer, this.view.byteOffset + this.getDataDirectoryOffset());
    }
    getDataDirectoryOffset() {
        let off = ImageFileHeader.size + 4;
        const magic = this.view.getUint16(off, true);
        if (magic === ImageOptionalHeader64.DEFAULT_MAGIC) {
            off += ImageOptionalHeader64.size;
        }
        else {
            off += ImageOptionalHeader.size;
        }
        return off;
    }
    getSectionHeaderOffset() {
        return this.getDataDirectoryOffset() + ImageDataDirectoryArray.size;
    }
}
//# sourceMappingURL=ImageNtHeaders.js.map