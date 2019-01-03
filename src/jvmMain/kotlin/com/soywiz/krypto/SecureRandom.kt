package com.soywiz.krypto

import com.soywiz.krypto.internal.arraycopy
import java.security.SecureRandom
import kotlin.random.Random

actual class SecureRandom : Random() {
    private val jrandom = SecureRandom()

    override fun nextBytes(array: ByteArray, fromIndex: Int, toIndex: Int): ByteArray {
        val temp = ByteArray(toIndex - fromIndex)
        jrandom.nextBytes(temp)
        arraycopy(temp, 0, array, fromIndex, temp.size)
        return array
    }

    override fun nextBits(bitCount: Int): Int = jrandom.nextInt(1 shl bitCount)
}
