package com.soywiz.krypto

import com.soywiz.krypto.internal.rotateLeft
import kotlin.math.abs
import kotlin.math.sin

internal object MD5 {
    private val S = intArrayOf(7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21)
    private val T = IntArray(64) { ((1L shl 32) * abs(sin(1.0 + it))).toLong().toInt() }

    fun digest(m: ByteArray): ByteArray {
        val nblocks = ((m.size + 8) / 64) + 1
        val tlen = nblocks * 64
        val pad = ByteArray(tlen - m.size).apply { this[0] = 0x80.toByte() }
        val bits = (m.size * 8).toLong()
        for (i in 0 until 8) pad[pad.size - 8 + i] = (bits ushr (8 * i)).toByte()

        val r = intArrayOf(0x67452301, 0xEFCDAB89.toInt(), 0x98BADCFE.toInt(), 0x10325476)
        val o = IntArray(4)
        val b = IntArray(16)

        for (i in 0 until tlen step 64) {
            for (j in 0 until 64) {
                val index = i + j
                val t = if (index < m.size) m[index] else pad[index - m.size]
                b[j ushr 2] = (t.toInt() shl 24) or (b[j ushr 2] ushr 8)
            }

            for (j in 0 until 4) o[j] = r[j]

            for (j in 0 until 64) {
                val d16 = j / 16
                val f = when (d16) {
                    0 -> (r[1] and r[2]) or (r[1].inv() and r[3])
                    1 -> (r[1] and r[3]) or (r[2] and r[3].inv())
                    2 -> r[1] xor r[2] xor r[3]
                    3 -> r[2] xor (r[1] or r[3].inv())
                    else -> 0
                }

                val bi = when (d16) {
                    0 -> j
                    1 -> (j * 5 + 1) and 0x0F
                    2 -> (j * 3 + 5) and 0x0F
                    3 -> (j * 7) and 0x0F
                    else -> 0
                }

                val temp = r[1] + (r[0] + f + b[bi] + T[j]).rotateLeft(S[(d16 shl 2) or (j and 3)])
                r[0] = r[3]
                r[3] = r[2]
                r[2] = r[1]
                r[1] = temp
            }

            for (j in 0 until 4) r[j] += o[j]
        }

        return ByteArray(16) { (r[it / 4] ushr ((it % 4) * 8)).toByte() }
    }
}
