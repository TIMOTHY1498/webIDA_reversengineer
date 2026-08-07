import { getFixedString, setFixedString } from './functions.js';
import ArrayFormatBase from './ArrayFormatBase.js';
export default class ImageSectionHeaderArray extends ArrayFormatBase {
    length;
    static itemSize = 40;
    constructor(view, length) {
        super(view);
        this.length = length;
    }
    static from(bin, length, offset = 0) {
        const size = length * 40;
        return new ImageSectionHeaderArray(new DataView(bin, offset, size), length);
    }
    get(index) {
        return {
            name: getFixedString(this.view, index * 40, 8),
            virtualSize: this.view.getUint32(8 + index * 40, true),
            virtualAddress: this.view.getUint32(12 + index * 40, true),
            sizeOfRawData: this.view.getUint32(16 + index * 40, true),
            pointerToRawData: this.view.getUint32(20 + index * 40, true),
            pointerToRelocations: this.view.getUint32(24 + index * 40, true),
            pointerToLineNumbers: this.view.getUint32(28 + index * 40, true),
            numberOfRelocations: this.view.getUint16(32 + index * 40, true),
            numberOfLineNumbers: this.view.getUint16(34 + index * 40, true),
            characteristics: this.view.getUint32(36 + index * 40, true),
        };
    }
    set(index, data) {
        setFixedString(this.view, index * 40, 8, data.name);
        this.view.setUint32(8 + index * 40, data.virtualSize, true);
        this.view.setUint32(12 + index * 40, data.virtualAddress, true);
        this.view.setUint32(16 + index * 40, data.sizeOfRawData, true);
        this.view.setUint32(20 + index * 40, data.pointerToRawData, true);
        this.view.setUint32(24 + index * 40, data.pointerToRelocations, true);
        this.view.setUint32(28 + index * 40, data.pointerToLineNumbers, true);
        this.view.setUint16(32 + index * 40, data.numberOfRelocations, true);
        this.view.setUint16(34 + index * 40, data.numberOfLineNumbers, true);
        this.view.setUint32(36 + index * 40, data.characteristics, true);
    }
}
//# sourceMappingURL=ImageSectionHeaderArray.js.map