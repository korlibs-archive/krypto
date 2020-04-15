@file:Suppress("RedundantSemicolon", "RedundantSemicolon")

package com.soywiz.krypto

import com.soywiz.krypto.encoding.Hex

// https://github.com/emn178/js-sha3/blob/master/src/sha3.js
/**
 * [js-sha3]{@link https://github.com/emn178/js-sha3}
 *
 * @version 0.8.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2015-2018
 * @license MIT
 */

private object SHA3Impl {
    val SHAKE_PADDING = intArrayOf(31, 7936, 2031616, 520093696)
    val CSHAKE_PADDING = intArrayOf(4, 1024, 262144, 67108864)
    val KECCAK_PADDING = intArrayOf(1, 256, 65536, 16777216)
    val PADDING = intArrayOf(6, 1536, 393216, 100663296)
    val SHIFT = intArrayOf(0, 8, 16, 24)
    val RC = intArrayOf(1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
        0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
        2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
        2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
        2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648)
    val BITS = intArrayOf(224, 256, 384, 512)
    val SHAKE_BITS = intArrayOf(128, 256)
    val CSHAKE_BYTEPAD = mapOf(
        "128" to 168,
        "256" to 136
    )

    fun createOutputMethod(bits: Int, padding: Int, outputType: String) {
        return { message ->
            return Keccak(bits, padding, bits).update(message)[outputType]();
        }
    }

    fun createShakeOutputMethod(bits: Int, padding: Int, outputType: String) {
        return { message, outputBits ->
            return Keccak(bits, padding, outputBits).update(message)[outputType]();
        }
    }

    fun createCshakeOutputMethod(bits: Int, padding: Int, outputType: String) {
        return { message, outputBits, n, s ->
            return methods['cshake' + bits].update(message, outputBits, n, s)[outputType]();
        }
    }

    fun createKmacOutputMethod(bits: Int, padding: Int, outputType: String) {
        return { key, message, outputBits, s ->
            return methods['kmac' + bits].update(key, message, outputBits, s)[outputType]();
        }
    }

    fun createOutputMethods(method, createMethod, bits, padding) {
        for (i in 0 until OUTPUT_TYPES.length) {
            var type = OUTPUT_TYPES[i];
            method[type] = createMethod(bits, padding, type);
        }
        return method;
    };

    fun createMethod (bits: Int, padding: Int) {
        var method = createOutputMethod(bits, padding, "hex");
        method.create = function () {
            return new Keccak(bits, padding, bits);
        };
        method.update = function (message) {
            return method.create().update(message);
        };
        return createOutputMethods(method, createOutputMethod, bits, padding);
    };

    fun createShakeMethod(bits, padding) {
        var method = createShakeOutputMethod(bits, padding, "hex");
        method.create = function (outputBits) {
            return new Keccak(bits, padding, outputBits);
        };
        method.update = function (message, outputBits) {
            return method.create(outputBits).update(message);
        };
        return createOutputMethods(method, createShakeOutputMethod, bits, padding);
    };

    fun createCshakeMethod(bits, padding) {
        var w = CSHAKE_BYTEPAD[bits];
        var method = createCshakeOutputMethod(bits, padding, "hex");
        method.create = { outputBits, n, s ->
            if (!n && !s) {
                return methods['shake' + bits].create(outputBits);
            } else {
                return new Keccak(bits, padding, outputBits).bytepad([n, s], w);
            }
        };
        method.update = { message, outputBits, n, s ->
            return method.create(outputBits, n, s).update(message);
        };
        return createOutputMethods(method, createCshakeOutputMethod, bits, padding);
    };

    fun createKmacMethod(bits: Int, padding: Int) {
        var w = CSHAKE_BYTEPAD[bits];
        var method = createKmacOutputMethod(bits, padding, "hex");
        method.create = { key, outputBits, s,
            return new Kmac(bits, padding, outputBits).bytepad(['KMAC', s], w).bytepad([key], w);
        };
        method.update = { key, message, outputBits, s ->
            return method.create(key, outputBits, s).update(message);
        };
        return createOutputMethods(method, createKmacOutputMethod, bits, padding);
    };

    data class Algo(val name: String, val padding: IntArray, val bits: IntArray, val createMethod: Any)

    val algorithms = listOf(
        Algo(name = "keccak", padding = KECCAK_PADDING, bits = BITS, createMethod = createMethod),
        Algo(name = "sha3", padding = PADDING, bits = BITS, createMethod = createMethod),
        Algo(name = "shake", padding = SHAKE_PADDING, bits = SHAKE_BITS, createMethod = createShakeMethod),
        Algo(name = "cshake", padding = CSHAKE_PADDING, bits = SHAKE_BITS, createMethod = createCshakeMethod),
        Algo(name = "kmac", padding = CSHAKE_PADDING, bits = SHAKE_BITS, createMethod = createKmacMethod)
    )

    var methods = LinkedHashMap<String, Algo>()
    var methodNames = arrayListOf<String>()

    init {
        for (i in 0 until algorithms.size) {
            val algorithm = algorithms[i];
            val bits = algorithm.bits;
            for (j in 0 until bits.size) {
                val methodName = algorithm.name + '_' + bits[j];
                methodNames.add(methodName);
                methods[methodName] = algorithm.createMethod(bits[j], algorithm.padding);
                if (algorithm.name != "sha3") {
                    val newMethodName = algorithm.name + bits[j];
                    methodNames.add(newMethodName);
                    methods[newMethodName] = methods[methodName];
                }
            }
        }
    }

    open class Keccak(bits: Int, padding: Int, outputBits: Int) {
        var blocks = [];
        var s = IntArray(50)
        var padding = padding;
        var outputBits = outputBits;
        var reset = true;
        var finalized = false;
        var block = 0;
        var start = 0;
        var blockCount = (1600 - (bits shl 1)) shr 5;
        var byteCount = this.blockCount shl 2;
        var outputBlocks = outputBits shr 5;
        var extraBytes = (outputBits and 31) shr 3;
        var lastByteIndex: Int = 0

        fun update(message) {
            if (this.finalized) {
                throw new Error(FINALIZE_ERROR);
            }
            var notString, type = typeof message;
            if (type !== 'string') {
                if (type === 'object') {
                    if (message === null) {
                        throw new Error(INPUT_ERROR);
                    } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
                        message = new Uint8Array(message);
                    } else if (!Array.isArray(message)) {
                        if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
                            throw new Error(INPUT_ERROR);
                        }
                    }
                } else {
                    throw new Error(INPUT_ERROR);
                }
                notString = true;
            }
            var blocks = this.blocks
            var byteCount = this.byteCount
            var length = message.length,
            var blockCount = this.blockCount
            var index = 0
            var s = this.s
            var i: Int
            var code: Int

            while (index < length) {
                if (this.reset) {
                    this.reset = false;
                    blocks[0] = this.block;
                    i = 1
                    while (i < blockCount + 1) {
                        blocks[i] = 0;
                        ++i
                    }
                }
                if (notString) {
                    i = this.start
                    while (index < length && i < byteCount) {
                        blocks[i shr 2] = blocks[i shr 2] or (message[index] shl SHIFT[i++ and 3])
                        ++index
                    }
                } else {
                    i = this.start
                    while (index < length && i < byteCount) {
                        code = message.charCodeAt(index);
                        if (code < 0x80) {
                            blocks[i shr 2] = blocks[i shr 2] or code shl SHIFT[i++ and 3];
                        } else if (code < 0x800) {
                            blocks[i shr 2] = blocks[i shr 2] or (0xc0 or (code shr 6)) shl SHIFT[i++ and 3];
                            blocks[i shr 2] = blocks[i shr 2] or (0x80 or (code and 0x3f)) shl SHIFT[i++ and 3];
                        } else if (code < 0xd800 || code >= 0xe000) {
                            blocks[i shr 2] = blocks[i shr 2] or (0xe0 or (code shr 12)) shl SHIFT[i++ and 3];
                            blocks[i shr 2] = blocks[i shr 2] or (0x80 or ((code shr 6) and 0x3f)) shl SHIFT[i++ and 3];
                            blocks[i shr 2] = blocks[i shr 2] or (0x80 or (code and 0x3f)) shl SHIFT[i++ and 3];
                        } else {
                            code = 0x10000 + (((code and 0x3ff) shl 10) or (message.charCodeAt(++index) and 0x3ff));
                            blocks[i shr 2] = blocks[i shr 2] or (0xf0 or (code shr 18)) shl SHIFT[i++ and 3];
                            blocks[i shr 2] = blocks[i shr 2] or (0x80 or ((code shr 12) and 0x3f)) shl SHIFT[i++ and 3];
                            blocks[i shr 2] = blocks[i shr 2] or (0x80 or ((code shr 6) and 0x3f)) shl SHIFT[i++ and 3];
                            blocks[i shr 2] = blocks[i shr 2] or (0x80 or (code and 0x3f)) shl SHIFT[i++ and 3];
                        }

                        ++index
                    }
                }
                this.lastByteIndex = i;
                if (i >= byteCount) {
                    this.start = i - byteCount;
                    this.block = blocks[blockCount];
                    i = 0
                    while (i < blockCount) {
                        s[i] = s[i] xor blocks[i];
                        ++i
                    }
                    f(s);
                    this.reset = true;
                } else {
                    this.start = i;
                }
            }
            return this;
        };

        fun encode(x: Int, right: Boolean): Int {
            var o = x and 255
            var n = 1;
            val bytes = arrayListOf<Int>(o);
            var x = x shr 8;
            o = x and 255;
            while (o > 0) {
                bytes.add(0, o)
                x = x shr 8;
                o = x and 255;
                ++n;
            }
            if (right) {
                bytes.add(n);
            } else {
                bytes.add(0, n);
            }
            this.update(bytes);
            return bytes.size;
        };

        fun encodeString(str: String) {
            var notString
            var type = typeof str;
            if (type !== 'string') {
                if (type === 'object') {
                    if (str === null) {
                        throw new Error(INPUT_ERROR);
                    } else if (ARRAY_BUFFER && str.constructor === ArrayBuffer) {
                        str = new Uint8Array(str);
                    } else if (!Array.isArray(str)) {
                        if (!ARRAY_BUFFER || !ArrayBuffer.isView(str)) {
                            throw new Error(INPUT_ERROR);
                        }
                    }
                } else {
                    throw new Error(INPUT_ERROR);
                }
                notString = true;
            }
            var bytes = 0, length = str.length;
            if (notString) {
                bytes = length;
            } else {
                for (i in 0 until str.length) {
                    var code = str.charCodeAt(i);
                    if (code < 0x80) {
                        bytes += 1;
                    } else if (code < 0x800) {
                        bytes += 2;
                    } else if (code < 0xd800 || code >= 0xe000) {
                        bytes += 3;
                    } else {
                        code = 0x10000 + (((code and 0x3ff) shl 10) or (str.charCodeAt(++i) and 0x3ff));
                        bytes += 4;
                    }
                }
            }
            bytes += this.encode(bytes * 8);
            this.update(str);
            return bytes;
        };

        fun bytepad(strs, w) {
            var bytes = this.encode(w);
            for (var i = 0; i < strs.length; ++i) {
                bytes += this.encodeString(strs[i]);
            }
            var paddingBytes = w - bytes % w;
            var zeros = [];
            zeros.length = paddingBytes;
            this.update(zeros);
            return this;
        };

        open fun finalize() {
            if (this.finalized) {
                return;
            }
            this.finalized = true;
            var blocks = this.blocks
            var i = this.lastByteIndex
            var blockCount = this.blockCount
            var s = this.s;
            blocks[i shr 2] = blocks[i shr 2] or this.padding[i and 3];
            if (this.lastByteIndex === this.byteCount) {
                blocks[0] = blocks[blockCount];
                for (i in 1 until blockCount + 1) {
                    blocks[i] = 0;
                }
            }
            blocks[blockCount - 1] = blocks[blockCount - 1] or 0x80000000;
            for (i in 0 until blockCount) {
                s[i] = s[i] xor blocks[i];
            }
            f(s);
        };

        fun hex() {
            this.finalize();
            val HEX_CHARS = Hex.DIGITS_LOWER

            var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
            extraBytes = this.extraBytes
            var i = 0
            var j = 0;
            var hex = ''
            var block;
            while (j < outputBlocks) {
                i = 0
                while (i < blockCount && j < outputBlocks) {
                    block = s[i];
                    hex += HEX_CHARS[(block shr 4) and 0x0F] + HEX_CHARS[block and 0x0F] +
                    HEX_CHARS[(block shr 12) and 0x0F] + HEX_CHARS[(block shr 8) and 0x0F] +
                    HEX_CHARS[(block shr 20) and 0x0F] + HEX_CHARS[(block shr 16) and 0x0F] +
                    HEX_CHARS[(block shr 28) and 0x0F] + HEX_CHARS[(block shr 24) and 0x0F];
                    ++i
                    ++j
                }
                if (j % blockCount === 0) {
                    f(s);
                    i = 0;
                }
            }
            if (extraBytes) {
                block = s[i];
                hex += HEX_CHARS[(block shr 4) and 0x0F] + HEX_CHARS[block and 0x0F];
                if (extraBytes > 1) {
                    hex += HEX_CHARS[(block shr 12) and 0x0F] + HEX_CHARS[(block shr 8) and 0x0F];
                }
                if (extraBytes > 2) {
                    hex += HEX_CHARS[(block shr 20) and 0x0F] + HEX_CHARS[(block shr 16) and 0x0F];
                }
            }
            return hex;
        };

        fun arrayBuffer() {
            this.finalize();

            var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
            extraBytes = this.extraBytes, i = 0, j = 0;
            var bytes = this.outputBits shr 3;
            var buffer;
            if (extraBytes) {
                buffer = new ArrayBuffer((outputBlocks + 1) shl 2);
            } else {
                buffer = new ArrayBuffer(bytes);
            }
            var array = new Uint32Array(buffer);
            while (j < outputBlocks) {
                for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
                    array[j] = s[i];
                }
                if (j % blockCount === 0) {
                    f(s);
                }
            }
            if (extraBytes) {
                array[i] = s[i];
                buffer = buffer.slice(0, bytes);
            }
            return buffer;
        };

        val buffer get() = arrayBuffer;

        fun digest(): ByteArray {
            this.finalize();

            var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
            extraBytes = this.extraBytes
            var i = 0
            var j = 0;
            var array = []
            var offset
            var block;
            while (j < outputBlocks) {
                i = 0
                while (i < blockCount && j < outputBlocks) {
                    offset = j shl 2;
                    block = s[i];
                    array[offset] = block and 0xFF;
                    array[offset + 1] = (block shr 8) and 0xFF;
                    array[offset + 2] = (block shr 16) and 0xFF;
                    array[offset + 3] = (block shr 24) and 0xFF;
                    ++i
                    ++j
                }
                if (j % blockCount == 0) {
                    f(s);
                }
            }
            if (extraBytes != 0) {
                offset = j shl 2;
                block = s[i];
                array[offset] = block and 0xFF;
                if (extraBytes > 1) {
                    array[offset + 1] = (block shr 8) and 0xFF;
                }
                if (extraBytes > 2) {
                    array[offset + 2] = (block shr 16) and 0xFF;
                }
            }
            return array;
        };

    }

    class Kmac(bits: Int, padding: Int, outputBits: Int) : Keccak(bits, padding, outputBits) {
        override fun finalize() {
            this.encode(this.outputBits, true);
            return super.finalize()
        };
    }


    fun f (s) {
        var h = 0
        var l = 0
        var n = 0
        var c0 = 0
        var c1 = 0
        var c2 = 0
        var c3 = 0
        var c4 = 0
        var c5 = 0
        var c6 = 0
        var c7 = 0
        var c8 = 0
        var c9 = 0
        var b0 = 0
        var b1 = 0
        var b2 = 0
        var b3 = 0
        var b4 = 0
        var b5 = 0
        var b6 = 0
        var b7 = 0
        var b8 = 0
        var b9 = 0
        var b10 = 0
        var b11 = 0
        var b12 = 0
        var b13 = 0
        var b14 = 0
        var b15 = 0
        var b16 = 0
        var b17 = 0
        var b18 = 0
        var b19 = 0
        var b20 = 0
        var b21 = 0
        var b22 = 0
        var b23 = 0
        var b24 = 0
        var b25 = 0
        var b26 = 0
        var b27 = 0
        var b28 = 0
        var b29 = 0
        var b30 = 0
        var b31 = 0
        var b32 = 0
        var b33 = 0
        var b34 = 0
        var b35 = 0
        var b36 = 0
        var b37 = 0
        var b38 = 0
        var b39 = 0
        var b40 = 0
        var b41 = 0
        var b42 = 0
        var b43 = 0
        var b44 = 0
        var b45 = 0
        var b46 = 0
        var b47 = 0
        var b48 = 0
        var b49 = 0
        for (n in 0 until 48 step 2) {
            c0 = s[0] xor s[10] xor s[20] xor s[30] xor s[40];
            c1 = s[1] xor s[11] xor s[21] xor s[31] xor s[41];
            c2 = s[2] xor s[12] xor s[22] xor s[32] xor s[42];
            c3 = s[3] xor s[13] xor s[23] xor s[33] xor s[43];
            c4 = s[4] xor s[14] xor s[24] xor s[34] xor s[44];
            c5 = s[5] xor s[15] xor s[25] xor s[35] xor s[45];
            c6 = s[6] xor s[16] xor s[26] xor s[36] xor s[46];
            c7 = s[7] xor s[17] xor s[27] xor s[37] xor s[47];
            c8 = s[8] xor s[18] xor s[28] xor s[38] xor s[48];
            c9 = s[9] xor s[19] xor s[29] xor s[39] xor s[49];
    
            h = c8 xor ((c2 shl 1) or (c3 ushr 31));
            l = c9 xor ((c3 shl 1) or (c2 ushr 31));
            s[0] ^= h;
            s[1] ^= l;
            s[10] ^= h;
            s[11] ^= l;
            s[20] ^= h;
            s[21] ^= l;
            s[30] ^= h;
            s[31] ^= l;
            s[40] ^= h;
            s[41] ^= l;
            h = c0 xor ((c4 shl 1) or (c5 ushr 31));
            l = c1 xor ((c5 shl 1) or (c4 ushr 31));
            s[2] ^= h;
            s[3] ^= l;
            s[12] ^= h;
            s[13] ^= l;
            s[22] ^= h;
            s[23] ^= l;
            s[32] ^= h;
            s[33] ^= l;
            s[42] ^= h;
            s[43] ^= l;
            h = c2 xor ((c6 shl 1) or (c7 ushr 31));
            l = c3 xor ((c7 shl 1) or (c6 ushr 31));
            s[4] ^= h;
            s[5] ^= l;
            s[14] ^= h;
            s[15] ^= l;
            s[24] ^= h;
            s[25] ^= l;
            s[34] ^= h;
            s[35] ^= l;
            s[44] ^= h;
            s[45] ^= l;
            h = c4 xor ((c8 shl 1) or (c9 ushr 31));
            l = c5 xor ((c9 shl 1) or (c8 ushr 31));
            s[6] ^= h;
            s[7] ^= l;
            s[16] ^= h;
            s[17] ^= l;
            s[26] ^= h;
            s[27] ^= l;
            s[36] ^= h;
            s[37] ^= l;
            s[46] ^= h;
            s[47] ^= l;
            h = c6 xor ((c0 shl 1) or (c1 ushr 31));
            l = c7 xor ((c1 shl 1) or (c0 ushr 31));
            s[8] ^= h;
            s[9] ^= l;
            s[18] ^= h;
            s[19] ^= l;
            s[28] ^= h;
            s[29] ^= l;
            s[38] ^= h;
            s[39] ^= l;
            s[48] ^= h;
            s[49] ^= l;
    
            b0 = s[0];
            b1 = s[1];
            b32 = (s[11] shl 4) or (s[10] ushr 28);
            b33 = (s[10] shl 4) or (s[11] ushr 28);
            b14 = (s[20] shl 3) or (s[21] ushr 29);
            b15 = (s[21] shl 3) or (s[20] ushr 29);
            b46 = (s[31] shl 9) or (s[30] ushr 23);
            b47 = (s[30] shl 9) or (s[31] ushr 23);
            b28 = (s[40] shl 18) or (s[41] ushr 14);
            b29 = (s[41] shl 18) or (s[40] ushr 14);
            b20 = (s[2] shl 1) or (s[3] ushr 31);
            b21 = (s[3] shl 1) or (s[2] ushr 31);
            b2 = (s[13] shl 12) or (s[12] ushr 20);
            b3 = (s[12] shl 12) or (s[13] ushr 20);
            b34 = (s[22] shl 10) or (s[23] ushr 22);
            b35 = (s[23] shl 10) or (s[22] ushr 22);
            b16 = (s[33] shl 13) or (s[32] ushr 19);
            b17 = (s[32] shl 13) or (s[33] ushr 19);
            b48 = (s[42] shl 2) or (s[43] ushr 30);
            b49 = (s[43] shl 2) or (s[42] ushr 30);
            b40 = (s[5] shl 30) or (s[4] ushr 2);
            b41 = (s[4] shl 30) or (s[5] ushr 2);
            b22 = (s[14] shl 6) or (s[15] ushr 26);
            b23 = (s[15] shl 6) or (s[14] ushr 26);
            b4 = (s[25] shl 11) or (s[24] ushr 21);
            b5 = (s[24] shl 11) or (s[25] ushr 21);
            b36 = (s[34] shl 15) or (s[35] ushr 17);
            b37 = (s[35] shl 15) or (s[34] ushr 17);
            b18 = (s[45] shl 29) or (s[44] ushr 3);
            b19 = (s[44] shl 29) or (s[45] ushr 3);
            b10 = (s[6] shl 28) or (s[7] ushr 4);
            b11 = (s[7] shl 28) or (s[6] ushr 4);
            b42 = (s[17] shl 23) or (s[16] ushr 9);
            b43 = (s[16] shl 23) or (s[17] ushr 9);
            b24 = (s[26] shl 25) or (s[27] ushr 7);
            b25 = (s[27] shl 25) or (s[26] ushr 7);
            b6 = (s[36] shl 21) or (s[37] ushr 11);
            b7 = (s[37] shl 21) or (s[36] ushr 11);
            b38 = (s[47] shl 24) or (s[46] ushr 8);
            b39 = (s[46] shl 24) or (s[47] ushr 8);
            b30 = (s[8] shl 27) or (s[9] ushr 5);
            b31 = (s[9] shl 27) or (s[8] ushr 5);
            b12 = (s[18] shl 20) or (s[19] ushr 12);
            b13 = (s[19] shl 20) or (s[18] ushr 12);
            b44 = (s[29] shl 7) or (s[28] ushr 25);
            b45 = (s[28] shl 7) or (s[29] ushr 25);
            b26 = (s[38] shl 8) or (s[39] ushr 24);
            b27 = (s[39] shl 8) or (s[38] ushr 24);
            b8 = (s[48] shl 14) or (s[49] ushr 18);
            b9 = (s[49] shl 14) or (s[48] ushr 18);
    
            s[0] = b0 xor (b2.inv() and b4);
            s[1] = b1 xor (b3.inv() and b5);
            s[10] = b10 xor (b12.inv() and b14);
            s[11] = b11 xor (b13.inv() and b15);
            s[20] = b20 xor (b22.inv() and b24);
            s[21] = b21 xor (b23.inv() and b25);
            s[30] = b30 xor (b32.inv() and b34);
            s[31] = b31 xor (b33.inv() and b35);
            s[40] = b40 xor (b42.inv() and b44);
            s[41] = b41 xor (b43.inv() and b45);
            s[2] = b2 xor (b4.inv() and b6);
            s[3] = b3 xor (b5.inv() and b7);
            s[12] = b12 xor (b14.inv() and b16);
            s[13] = b13 xor (b15.inv() and b17);
            s[22] = b22 xor (b24.inv() and b26);
            s[23] = b23 xor (b25.inv() and b27);
            s[32] = b32 xor (b34.inv() and b36);
            s[33] = b33 xor (b35.inv() and b37);
            s[42] = b42 xor (b44.inv() and b46);
            s[43] = b43 xor (b45.inv() and b47);
            s[4] = b4 xor (b6.inv() and b8);
            s[5] = b5 xor (b7.inv() and b9);
            s[14] = b14 xor (b16.inv() and b18);
            s[15] = b15 xor (b17.inv() and b19);
            s[24] = b24 xor (b26.inv() and b28);
            s[25] = b25 xor (b27.inv() and b29);
            s[34] = b34 xor (b36.inv() and b38);
            s[35] = b35 xor (b37.inv() and b39);
            s[44] = b44 xor (b46.inv() and b48);
            s[45] = b45 xor (b47.inv() and b49);
            s[6] = b6 xor (b8.inv() and b0);
            s[7] = b7 xor (b9.inv() and b1);
            s[16] = b16 xor (b18.inv() and b10);
            s[17] = b17 xor (b19.inv() and b11);
            s[26] = b26 xor (b28.inv() and b20);
            s[27] = b27 xor (b29.inv() and b21);
            s[36] = b36 xor (b38.inv() and b30);
            s[37] = b37 xor (b39.inv() and b31);
            s[46] = b46 xor (b48.inv() and b40);
            s[47] = b47 xor (b49.inv() and b41);
            s[8] = b8 xor (b0.inv() and b2);
            s[9] = b9 xor (b1.inv() and b3);
            s[18] = b18 xor (b10.inv() and b12);
            s[19] = b19 xor (b11.inv() and b13);
            s[28] = b28 xor (b20.inv() and b22);
            s[29] = b29 xor (b21.inv() and b23);
            s[38] = b38 xor (b30.inv() and b32);
            s[39] = b39 xor (b31.inv() and b33);
            s[48] = b48 xor (b40.inv() and b42);
            s[49] = b49 xor (b41.inv() and b43);
    
            s[0] = s[0] xor RC[n];
            s[1] = s[1] xor RC[n + 1];
        }
    };
}
