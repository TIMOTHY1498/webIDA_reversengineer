import ArrayFormatBase from './ArrayFormatBase.js';
export default class ImageDataDirectoryArray extends ArrayFormatBase {
    static size = 128; // 16 * 8
    static itemSize = 8;
    length = 16;
    constructor(view) {
        super(view);
    }
    /** @note This does not clone binary data; the changes to the array will modify the specified buffer `bin` */
    static from(bin, offset = 0) {
        return new ImageDataDirectoryArray(new DataView(bin, offset, 128));
    }
    get(index) {
        return {
            virtualAddress: this.view.getUint32(index * 8, true),
            size: this.view.getUint32(4 + index * 8, true),
        };
    }
    set(index, data) {
        this.view.setUint32(index * 8, data.virtualAddress, true);
        this.view.setUint32(4 + index * 8, data.size, true);
    }
    findIndexByVirtualAddress(virtualAddress) {
        for (let i = 0; i < 16; ++i) {
            const va = this.view.getUint32(i * 8, true);
            const vs = this.view.getUint32(4 + i * 8, true);
            if (virtualAddress >= va && virtualAddress < va + vs) {
                return i;
            }
        }
        return null;
    }
}
//# sourceMappingURL=ImageDataDirectoryArray.js.map