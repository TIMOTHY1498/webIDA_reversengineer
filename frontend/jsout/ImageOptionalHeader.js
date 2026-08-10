import FormatBase from './FormatBase.js';
export default class ImageOptionalHeader extends FormatBase {
    static size = 96;
    static DEFAULT_MAGIC = 0x10b;
    constructor(view) {
        super(view);
    }
    static from(bin, offset = 0) {
        return new ImageOptionalHeader(new DataView(bin, offset, 96));
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
    get baseOfData() {
        return this.view.getUint32(24, true);
    }
    set baseOfData(val) {
        this.view.setUint32(24, val, true);
    }
    get imageBase() {
        return this.view.getUint32(28, true);
    }
    set imageBase(val) {
        this.view.setUint32(28, val, true);
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
        return this.view.getUint32(72, true);
    }
    set sizeOfStackReserve(val) {
        this.view.setUint32(72, val, true);
    }
    get sizeOfStackCommit() {
        return this.view.getUint32(76, true);
    }
    set sizeOfStackCommit(val) {
        this.view.setUint32(76, val, true);
    }
    get sizeOfHeapReserve() {
        return this.view.getUint32(80, true);
    }
    set sizeOfHeapReserve(val) {
        this.view.setUint32(80, val, true);
    }
    get sizeOfHeapCommit() {
        return this.view.getUint32(84, true);
    }
    set sizeOfHeapCommit(val) {
        this.view.setUint32(84, val, true);
    }
    get loaderFlags() {
        return this.view.getUint32(88, true);
    }
    set loaderFlags(val) {
        this.view.setUint32(88, val, true);
    }
    get numberOfRvaAndSizes() {
        return this.view.getUint32(92, true);
    }
    set numberOfRvaAndSizes(val) {
        this.view.setUint32(92, val, true);
    }
}
//# sourceMappingURL=ImageOptionalHeader.js.map