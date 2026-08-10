export default class FormatBase {
    view;
    constructor(view) {
        this.view = view;
    }
    copyTo(bin, offset) {
        new Uint8Array(bin, offset, this.view.byteLength).set(new Uint8Array(this.view.buffer, this.view.byteOffset, this.view.byteLength));
    }
    get byteLength() {
        return this.view.byteLength;
    }
}
//# sourceMappingURL=FormatBase.js.map