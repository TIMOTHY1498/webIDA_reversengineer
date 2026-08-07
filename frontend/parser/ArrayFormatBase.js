import FormatBase from './FormatBase.js';
/** abstract class that support array-like methods and 'for...of' operation */
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
class ArrayFormatBase extends FormatBase {
    constructor(view) {
        super(view);
    }
    forEach(callback) {
        const len = this.length;
        const a = [];
        a.length = len;
        for (let i = 0; i < len; ++i) {
            a[i] = this.get(i);
        }
        for (let i = 0; i < len; ++i) {
            callback(a[i], i, this);
        }
    }
    _iterator() {
        return new (class {
            base;
            i = 0;
            constructor(base) {
                this.base = base;
            }
            next() {
                if (this.i === this.base.length) {
                    return {
                        value: undefined,
                        done: true,
                    };
                }
                else {
                    return {
                        value: this.base.get(this.i++),
                        done: false,
                    };
                }
            }
        })(this);
    }
}
/* istanbul ignore else */
if (typeof Symbol !== 'undefined') {
    ArrayFormatBase.prototype[Symbol.iterator] =
        // eslint-disable-next-line @typescript-eslint/unbound-method
        ArrayFormatBase.prototype._iterator;
}
export default ArrayFormatBase;
//# sourceMappingURL=ArrayFormatBase.js.map