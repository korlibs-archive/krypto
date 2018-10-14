package com.soywiz.krypto

import kotlin.math.*

object SHA1 {
	private class Uint32ArrayBigEndian(val bytes: ByteArray) {
		constructor(length: Int) : this(ByteArray(length * 4))

		operator fun get(index: Int): Int = bytes.readS32_be(index * 4)
		operator fun set(index: Int, value: Int) = bytes.write32_be(index * 4, value)
	}

	private const val H0: Int = 0x67452301L.toInt()
	private const val H1: Int = 0xEFCDAB89L.toInt()
	private const val H2: Int = 0x98BADCFEL.toInt()
	private const val H3: Int = 0x10325476L.toInt()
	private const val H4: Int = 0xC3D2E1F0L.toInt()

	private const val K0020: Int = 0x5A827999L.toInt()
	private const val K2040: Int = 0x6ED9EBA1L.toInt()
	private const val K4060: Int = 0x8F1BBCDCL.toInt()
	private const val K6080: Int = 0xCA62C1D6L.toInt()

	fun hash(input: ByteArray): ByteArray {
		val inputBits: Long = input.size.toLong() * 8
		val minBits = inputBits + 65
		val bits = ceil((minBits.toDouble() / 512.0)).toInt() shl 9
		val bytes = bits / 8
		val slen = bytes / 4
		val s = Uint32ArrayBigEndian(slen)
		val w = IntArray(80)

		var h0 = H0
		var h1 = H1
		var h2 = H2
		var h3 = H3
		var h4 = H4

		for (i in 0 until input.size) s.bytes[i] = input[i]
		s.bytes[input.size] = 0x80.toByte()
		s[slen - 2] = (inputBits ushr 32).toInt()
		s[slen - 1] = (inputBits ushr 0).toInt()

		for (i in 0 until slen step 16) {
			for (j in 0 until 16) w[j] = s[i + j]
			for (j in 16 until 80) w[j] = (w[j - 3] xor w[j - 8] xor w[j - 14] xor w[j - 16]).rotateLeft(1)

			var a = h0
			var b = h1
			var c = h2
			var d = h3
			var e = h4

			for (j in 0 until 80) {
				val temp = a.rotateLeft(5) + e + w[j] + when (j) {
					in 0 until 20 -> ((b and c) or ((b.inv()) and d)) + K0020
					in 20 until 40 -> (b xor c xor d) + K2040
					in 40 until 60 -> ((b and c) xor (b and d) xor (c and d)) + K4060
					else -> (b xor c xor d) + K6080
				}

				e = d
				d = c
				c = b.rotateLeft(30)
				b = a
				a = temp
			}

			h0 = (h0 + a)
			h1 = (h1 + b)
			h2 = (h2 + c)
			h3 = (h3 + d)
			h4 = (h4 + e)
		}

		return ByteArray(4 * 5).apply {
			write32_be(0, h0)
			write32_be(4, h1)
			write32_be(8, h2)
			write32_be(12, h3)
			write32_be(16, h4)
		}
	}

	private fun Int.rotateLeft(bits: Int): Int = ((this shl bits) or (this ushr (32 - bits)))

	private fun Int.extract8(offset: Int): Int = (this ushr offset) and 0xFF
	private fun ByteArray.write32_be(o: Int, v: Int) = run {
		this[o + 3] = v.extract8(0).toByte(); this[o + 2] = v.extract8(8).toByte(); this[o + 1] =
			v.extract8(16).toByte(); this[o + 0] = v.extract8(24).toByte()
	}

	private fun ByteArray.readU8(o: Int): Int = this[o].toInt() and 0xFF
	private fun ByteArray.readS32_be(o: Int): Int =
		(readU8(o + 3) shl 0) or (readU8(o + 2) shl 8) or (readU8(o + 1) shl 16) or (readU8(o + 0) shl 24)
}
