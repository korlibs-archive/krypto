package com.soywiz.krypto

import com.soywiz.krypto.internal.arraycopy
import org.khronos.webgl.Int8Array
import org.khronos.webgl.Uint8Array
import kotlin.random.Random

private val isNodeJs by lazy { js("(typeof process === 'object' && typeof require === 'function')").unsafeCast<Boolean>() }
private external fun require(name: String): dynamic
private val global: dynamic = js("(typeof global !== 'undefined') ? global : self")

actual class SecureRandom : Random() {
    private fun fillRandom(array: ByteArray): ByteArray {
        if (isNodeJs) {
            require("crypto").randomFillSync(Uint8Array(array.unsafeCast<Int8Array>().buffer))
        } else {
            global.crypto.getRandomValues(array)
        }
        return array
    }

    private val temp = ByteArray(4)
    private fun getInt(): Int {
        fillRandom(temp)
        val a = temp[0].toInt() and 0xFF
        val b = temp[1].toInt() and 0xFF
        val c = temp[2].toInt() and 0xFF
        val d = temp[3].toInt() and 0xFF
        return (a shl 24) or (b shl 16) or (c shl 8) or (d shl 0)
    }

    override fun nextBytes(array: ByteArray, fromIndex: Int, toIndex: Int): ByteArray {
        val random = fillRandom(ByteArray(toIndex - fromIndex))
        arraycopy(random, 0, array, fromIndex, random.size)
        return array
    }

    override fun nextBits(bitCount: Int): Int {
        return getInt() and ((1 shl bitCount) - 1)
    }
}