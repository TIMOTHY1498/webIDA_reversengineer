import FormatBase from './FormatBase.js';
export default class ImageFileHeader extends FormatBase {
    static size = 20;
    constructor(view) {
        super(view);
    }
    static from(bin, offset = 0) {
        return new ImageFileHeader(new DataView(bin, offset, 20));
    }
    get machine() {
        return this.view.getUint16(0, true);
    }
    set machine(val) {
        this.view.setUint16(0, val, true);
    }
    get numberOfSections() {
        return this.view.getUint16(2, true);
    }
    set numberOfSections(val) {
        this.view.setUint16(2, val, true);
    }
    get timeDateStamp() {
        return this.view.getUint32(4, true);
    }
    set timeDateStamp(val) {
        this.view.setUint32(4, val, true);
    }
    get pointerToSymbolTable() {
        return this.view.getUint32(8, true);
    }
    set pointerToSymbolTable(val) {
        this.view.setUint32(8, val, true);
    }
    get numberOfSymbols() {
        return this.view.getUint32(12, true);
    }
    set numberOfSymbols(val) {
        this.view.setUint32(12, val, true);
    }
    get sizeOfOptionalHeader() {
        return this.view.getUint16(16, true);
    }
    set sizeOfOptionalHeader(val) {
        this.view.setUint16(16, val, true);
    }
    get characteristics() {
        return this.view.getUint16(18, true);
    }
    set characteristics(val) {
        this.view.setUint16(18, val, true);
    }
}
//# sourceMappingURL=ImageFileHeader.js.map