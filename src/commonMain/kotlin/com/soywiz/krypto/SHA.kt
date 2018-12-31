package com.soywiz.krypto

import com.soywiz.krypto.internal.arraycopy
import com.soywiz.krypto.internal.readS32_be
import com.soywiz.krypto.internal.rotateLeft
import com.soywiz.krypto.internal.rotateRight

class SHA1 : BaseHash(chunkSize = 64, digestSize = 20) {
    companion object : HashProvider<SHA1> {
        override fun create(): SHA1 = SHA1()

        private val H = intArrayOf(
            0x67452301L.toInt(),
            0xEFCDAB89L.toInt(),
            0x98BADCFEL.toInt(),
            0x10325476L.toInt(),
            0xC3D2E1F0L.toInt()
        )

        private const val K0020: Int = 0x5A827999L.toInt()
        private const val K2040: Int = 0x6ED9EBA1L.toInt()
        private const val K4060: Int = 0x8F1BBCDCL.toInt()
        private const val K6080: Int = 0xCA62C1D6L.toInt()
    }

    private val w = IntArray(80)
    private val h = IntArray(5)

    override fun reset(): Hash = this.apply { arraycopy(H, 0, h, 0, 5) }

    init {
        reset()
    }

    override fun generatePadding(totalWritten: Long): ByteArray = shaGeneratePadding(totalWritten)

    override fun core(chunk: ByteArray) {
        for (j in 0 until 16) w[j] = chunk.readS32_be(j * 4)
        for (j in 16 until 80) w[j] = (w[j - 3] xor w[j - 8] xor w[j - 14] xor w[j - 16]).rotateLeft(1)

        var a = h[0]
        var b = h[1]
        var c = h[2]
        var d = h[3]
        var e = h[4]

        for (j in 0 until 80) {
            val temp = a.rotateLeft(5) + e + w[j] + when (j / 20) {
                0 -> ((b and c) or ((b.inv()) and d)) + K0020
                1 -> (b xor c xor d) + K2040
                2 -> ((b and c) xor (b and d) xor (c and d)) + K4060
                else -> (b xor c xor d) + K6080
            }

            e = d
            d = c
            c = b.rotateLeft(30)
            b = a
            a = temp
        }

        h[0] += a
        h[1] += b
        h[2] += c
        h[3] += d
        h[4] += e
    }

    override fun digestCore(out: ByteArray) {
        for (n in out.indices) out[n] = (h[n / 4] ushr (24 - 8 * (n % 4))).toByte()
    }
}


class SHA256 : BaseHash(chunkSize = 64, digestSize = 32) {
    companion object : HashProvider<SHA256> {
        override fun create(): SHA256 = SHA256()

        private val H = intArrayOf(
            0x6a09e667, -0x4498517b, 0x3c6ef372, -0x5ab00ac6,
            0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19
        )

        private val K = intArrayOf(
            0x428a2f98, 0x71374491, -0x4a3f0431, -0x164a245b,
            0x3956c25b, 0x59f111f1, -0x6dc07d5c, -0x54e3a12b,
            -0x27f85568, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
            -0x1b64963f, -0x1041b87a, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            -0x67c1aeae, -0x57ce3993, -0x4ffcd838, -0x40a68039,
            -0x391ff40d, -0x2a586eb9, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, -0x7e3d36d2, -0x6d8dd37b,
            -0x5d40175f, -0x57e599b5, -0x3db47490, -0x3893ae5d,
            -0x2e6d17e7, -0x2966f9dc, -0xbf1ca7b, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, -0x7b3787ec, -0x7338fdf8,
            -0x6f410006, -0x5baf9315, -0x41065c09, -0x398e870e
        )
    }


    private val h = IntArray(8)
    private val r = IntArray(8)
    private val w = IntArray(64)

    init {
        reset()
    }

    override fun reset(): Hash = this.apply { arraycopy(H, 0, h, 0, 8) }

    override fun core(chunk: ByteArray) {
        arraycopy(h, 0, r, 0, 8)

        for (j in 0 until 16) w[j] = chunk.readS32_be(j * 4)
        for (j in 16 until 64) {
            val s0 = w[j - 15].rotateRight(7) xor w[j - 15].rotateRight(18) xor w[j - 15].ushr(3)
            val s1 = w[j - 2].rotateRight(17) xor w[j - 2].rotateRight(19) xor w[j - 2].ushr(10)
            w[j] = w[j - 16] + s0 + w[j - 7] + s1
        }

        for (j in 0 until 64) {
            val s1 = r[4].rotateRight(6) xor r[4].rotateRight(11) xor r[4].rotateRight(25)
            val ch = r[4] and r[5] xor (r[4].inv() and r[6])
            val t1 = r[7] + s1 + ch + K[j] + w[j]
            val s0 = r[0].rotateRight(2) xor r[0].rotateRight(13) xor r[0].rotateRight(22)
            val maj = r[0] and r[1] xor (r[0] and r[2]) xor (r[1] and r[2])
            val t2 = s0 + maj
            r[7] = r[6]
            r[6] = r[5]
            r[5] = r[4]
            r[4] = r[3] + t1
            r[3] = r[2]
            r[2] = r[1]
            r[1] = r[0]
            r[0] = t1 + t2

        }
        for (j in 0 until 8) h[j] += r[j]
    }

    override fun generatePadding(totalWritten: Long): ByteArray = shaGeneratePadding(totalWritten)

    override fun digestCore(out: ByteArray) {
        for (n in out.indices) out[n] = (h[n / 4] ushr (24 - 8 * (n % 4))).toByte()
    }
}

private fun shaGeneratePadding(totalWritten: Long): ByteArray {
    val tail = totalWritten % 64
    val padding = (if (64 - tail >= 9) 64 - tail else 128 - tail)
    val pad = ByteArray(padding.toInt()).apply { this[0] = 0x80.toByte() }
    val bits = (totalWritten * 8)
    for (i in 0 until 8) pad[pad.size - 1 - i] = ((bits ushr (8 * i)) and 0xFF).toByte()
    return pad
}