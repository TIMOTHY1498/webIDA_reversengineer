import { createDataView } from './functions.js';
import FormatBase from './FormatBase.js';
export default class ImageDosHeader extends FormatBase {
    static size = 64;
    static DEFAULT_MAGIC = 0x5a4d; // 'MZ'
    constructor(view) {
        super(view);
    }
    static from(bin, offset = 0) {
        return new ImageDosHeader(createDataView(bin, offset, 64));
    }
    isValid() {
        return this.magic === ImageDosHeader.DEFAULT_MAGIC;
    }
    get magic() {
        return this.view.getUint16(0, true);
    }
    set magic(val) {
        this.view.setUint16(0, val, true);
    }
    get lastPageSize() {
        return this.view.getUint16(2, true);
    }
    set lastPageSize(val) {
        this.view.setUint16(2, val, true);
    }
    get pages() {
        return this.view.getUint16(4, true);
    }
    set pages(val) {
        this.view.setUint16(4, val, true);
    }
    get relocations() {
        return this.view.getUint16(6, true);
    }
    set relocations(val) {
        this.view.setUint16(6, val, true);
    }
    get headerSizeInParagraph() {
        return this.view.getUint16(8, true);
    }
    set headerSizeInParagraph(val) {
        this.view.setUint16(8, val, true);
    }
    get minAllocParagraphs() {
        return this.view.getUint16(10, true);
    }
    set minAllocParagraphs(val) {
        this.view.setUint16(10, val, true);
    }
    get maxAllocParagraphs() {
        return this.view.getUint16(12, true);
    }
    set maxAllocParagraphs(val) {
        this.view.setUint16(12, val, true);
    }
    get initialSS() {
        return this.view.getUint16(14, true);
    }
    set initialSS(val) {
        this.view.setUint16(14, val, true);
    }
    get initialSP() {
        return this.view.getUint16(16, true);
    }
    set initialSP(val) {
        this.view.setUint16(16, val, true);
    }
    get checkSum() {
        return this.view.getUint16(18, true);
    }
    set checkSum(val) {
        this.view.setUint16(18, val, true);
    }
    get initialIP() {
        return this.view.getUint16(20, true);
    }
    set initialIP(val) {
        this.view.setUint16(20, val, true);
    }
    get initialCS() {
        return this.view.getUint16(22, true);
    }
    set initialCS(val) {
        this.view.setUint16(22, val, true);
    }
    get relocationTableAddress() {
        return this.view.getUint16(24, true);
    }
    set relocationTableAddress(val) {
        this.view.setUint16(24, val, true);
    }
    get overlayNum() {
        return this.view.getUint16(26, true);
    }
    set overlayNum(val) {
        this.view.setUint16(26, val, true);
    }
    // WORD e_res[4] (28,30,32,34)
    get oemId() {
        return this.view.getUint16(36, true);
    }
    set oemId(val) {
        this.view.setUint16(36, val, true);
    }
    get oemInfo() {
        return this.view.getUint16(38, true);
    }
    set oemInfo(val) {
        this.view.setUint16(38, val, true);
    }
    // WORD e_res2[10] (40,42,44,46,48,50,52,54,56,58)
    get newHeaderAddress() {
        return this.view.getUint32(60, true);
    }
    set newHeaderAddress(val) {
        this.view.setUint32(60, val, true);
    }
}
//# sourceMappingURL=ImageDosHeader.js.map