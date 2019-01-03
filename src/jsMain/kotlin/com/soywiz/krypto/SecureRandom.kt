package com.soywiz.krypto

import kotlin.random.Random

// @TODO
actual class SecureRandom : Random() {
    val krandom = Random
    override fun nextBits(bitCount: Int): Int = krandom.nextBits(bitCount)
}