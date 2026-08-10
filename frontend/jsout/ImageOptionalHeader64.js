import FormatBase from './FormatBase.js';
function getUint64LE(view, offset) {
    return (view.getUint32(offset + 4, true) * 0x100000000 +
        view.getUint32(offset, true));
}
function setUint64LE(view, offset, val) {
    view.setUint32(offset, val & 0xffffffff, true);
    view.setUint32(offset + 4, Math.floor(val / 0x100000000), true);
}
function getUint64LEBigInt(view, offset) {
    /* istanbul ignore if */
    if (typeof BigInt === 'undefined') {
        throw new Error('BigInt not supported');
    }
    return (BigInt(0x100000000) * BigInt(view.getUint32(offset + 4, true)) +
        BigInt(view.getUint32(offset, true)));
}
function setUint64LEBigInt(view, offset, val) {
    /* istanbul ignore if */
    if (typeof BigInt === 'undefined') {
        throw new Error('BigInt not supported');
    }
    view.setUint32(offset, Number(val & BigInt(0xffffffff)), true);
    view.setUint32(offset + 4, Math.floor(Number((val / BigInt(0x100000000)) & BigInt(0xffffffff))), true);
}
export default class ImageOptionalHeader64 extends FormatBase {
    static size = 112;
    static DEFAULT_MAGIC = 0x20b;
    constructor(view) {
        super(view);
    }
    static from(bin, offset = 0) {
        return new ImageOptionalHeader64(new DataView(bin, offset, 112));
    }
    get magic() {
        return this.view.getUint16(0, true);
    }
    set magic(val) {
        this.view.setUint16(0, val, true);
    }
    get majorLinkerVersion() {
        return this.view.getUint8(2);
    }
    set majorLinkerVersion(val) {
        this.view.setUint8(2, val);
    }
    get minorLinkerVersion() {
        return this.view.getUint8(3);
    }
    set minorLinkerVersion(val) {
        this.view.setUint8(3, val);
    }
    get sizeOfCode() {
        return this.view.getUint32(4, true);
    }
    set sizeOfCode(val) {
        this.view.setUint32(4, val, true);
    }
    get sizeOfInitializedData() {
        return this.view.getUint32(8, true);
    }
    set sizeOfInitializedData(val) {
        this.view.setUint32(8, val, true);
    }
    get sizeOfUninitializedData() {
        return this.view.getUint32(12, true);
    }
    set sizeOfUninitializedData(val) {
        this.view.setUint32(12, val, true);
    }
    get addressOfEntryPoint() {
        return this.view.getUint32(16, true);
    }
    set addressOfEntryPoint(val) {
        this.view.setUint32(16, val, true);
    }
    get baseOfCode() {
        return this.view.getUint32(20, true);
    }
    set baseOfCode(val) {
        this.view.setUint32(20, val, true);
    }
    get imageBase() {
        return getUint64LE(this.view, 24);
    }
    set imageBase(val) {
        setUint64LE(this.view, 24, val);
    }
    get imageBaseBigInt() {
        return getUint64LEBigInt(this.view, 24);
    }
    set imageBaseBigInt(val) {
        setUint64LEBigInt(this.view, 24, val);
    }
    get sectionAlignment() {
        return this.view.getUint32(32, true);
    }
    set sectionAlignment(val) {
        this.view.setUint32(32, val, true);
    }
    get fileAlignment() {
        return this.view.getUint32(36, true);
    }
    set fileAlignment(val) {
        this.view.setUint32(36, val, true);
    }
    get majorOperatingSystemVersion() {
        return this.view.getUint16(40, true);
    }
    set majorOperatingSystemVersion(val) {
        this.view.setUint16(40, val, true);
    }
    get minorOperatingSystemVersion() {
        return this.view.getUint16(42, true);
    }
    set minorOperatingSystemVersion(val) {
        this.view.setUint16(42, val, true);
    }
    get majorImageVersion() {
        return this.view.getUint16(44, true);
    }
    set majorImageVersion(val) {
        this.view.setUint16(44, val, true);
    }
    get minorImageVersion() {
        return this.view.getUint16(46, true);
    }
    set minorImageVersion(val) {
        this.view.setUint16(46, val, true);
    }
    get majorSubsystemVersion() {
        return this.view.getUint16(48, true);
    }
    set majorSubsystemVersion(val) {
        this.view.setUint16(48, val, true);
    }
    get minorSubsystemVersion() {
        return this.view.getUint16(50, true);
    }
    set minorSubsystemVersion(val) {
        this.view.setUint16(50, val, true);
    }
    get win32VersionValue() {
        return this.view.getUint32(52, true);
    }
    set win32VersionValue(val) {
        this.view.setUint32(52, val, true);
    }
    get sizeOfImage() {
        return this.view.getUint32(56, true);
    }
    set sizeOfImage(val) {
        this.view.setUint32(56, val, true);
    }
    get sizeOfHeaders() {
        return this.view.getUint32(60, true);
    }
    set sizeOfHeaders(val) {
        this.view.setUint32(60, val, true);
    }
    get checkSum() {
        return this.view.getUint32(64, true);
    }
    set checkSum(val) {
        this.view.setUint32(64, val, true);
    }
    get subsystem() {
        return this.view.getUint16(68, true);
    }
    set subsystem(val) {
        this.view.setUint16(68, val, true);
    }
    get dllCharacteristics() {
        return this.view.getUint16(70, true);
    }
    set dllCharacteristics(val) {
        this.view.setUint16(70, val, true);
    }
    get sizeOfStackReserve() {
        return getUint64LE(this.view, 72);
    }
    set sizeOfStackReserve(val) {
        setUint64LE(this.view, 72, val);
    }
    get sizeOfStackReserveBigInt() {
        return getUint64LEBigInt(this.view, 72);
    }
    set sizeOfStackReserveBigInt(val) {
        setUint64LEBigInt(this.view, 72, val);
    }
    get sizeOfStackCommit() {
        return getUint64LE(this.view, 80);
    }
    set sizeOfStackCommit(val) {
        setUint64LE(this.view, 80, val);
    }
    get sizeOfStackCommitBigInt() {
        return getUint64LEBigInt(this.view, 80);
    }
    set sizeOfStackCommitBigInt(val) {
        setUint64LEBigInt(this.view, 80, val);
    }
    get sizeOfHeapReserve() {
        return getUint64LE(this.view, 88);
    }
    set sizeOfHeapReserve(val) {
        setUint64LE(this.view, 88, val);
    }
    get sizeOfHeapReserveBigInt() {
        return getUint64LEBigInt(this.view, 88);
    }
    set sizeOfHeapReserveBigInt(val) {
        setUint64LEBigInt(this.view, 88, val);
    }
    get sizeOfHeapCommit() {
        return getUint64LE(this.view, 96);
    }
    set sizeOfHeapCommit(val) {
        setUint64LE(this.view, 96, val);
    }
    get sizeOfHeapCommitBigInt() {
        return getUint64LEBigInt(this.view, 96);
    }
    set sizeOfHeapCommitBigInt(val) {
        setUint64LEBigInt(this.view, 96, val);
    }
    get loaderFlags() {
        return this.view.getUint32(104, true);
    }
    set loaderFlags(val) {
        this.view.setUint32(104, val, true);
    }
    get numberOfRvaAndSizes() {
        return this.view.getUint32(108, true);
    }
    set numberOfRvaAndSizes(val) {
        this.view.setUint32(108, val, true);
    }
}
//# sourceMappingURL=ImageOptionalHeader64.js.map