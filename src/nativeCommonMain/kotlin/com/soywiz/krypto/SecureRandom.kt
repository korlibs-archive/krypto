package com.soywiz.krypto

import com.soywiz.krypto.internal.arraycopy
import kotlin.random.Random

// @TODO. This is not a secure source!
actual class SecureRandom : Random() {
    private val krandom = kotlin.random.Random

    override fun nextBits(bitCount: Int): Int = krandom.nextBits(bitCount)
}
