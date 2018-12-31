package com.soywiz.krypto

import com.soywiz.krypto.internal.arraycopy
import kotlin.math.min

interface HashProvider<T : Hash> {
    fun create(): T
}

interface Hash {
    val chunkSize: Int
    val digestSize: Int
    fun reset(): Hash
    fun update(data: ByteArray, offset: Int, count: Int): Hash
    fun digest(out: ByteArray)
}

abstract class BaseHash(override val chunkSize: Int, override val digestSize: Int) : Hash {
    private val chunk by lazy { ByteArray(chunkSize) }
    private var writtenInChunk = 0
    private var totalWritten = 0L

    override fun update(data: ByteArray, offset: Int, count: Int): Hash {
        var curr = offset
        var left = count
        while (left > 0) {
            val remainingInChunk = chunkSize - writtenInChunk
            val toRead = min(remainingInChunk, left)
            arraycopy(data, curr, chunk, writtenInChunk, toRead)
            left -= toRead
            curr += toRead
            writtenInChunk += toRead
            if (writtenInChunk >= chunkSize) {
                writtenInChunk -= chunkSize
                core(chunk)
            }
        }
        totalWritten += count
        return this
    }

    override fun digest(out: ByteArray) {
        val pad = generatePadding(totalWritten)
        var padPos = 0
        while (padPos < pad.size) {
            val padSize = chunkSize - writtenInChunk
            arraycopy(pad, padPos, chunk, writtenInChunk, padSize)
            core(chunk)
            writtenInChunk = 0
            padPos += padSize
        }

        digestCore(out)
        reset()
    }

    private fun generatePadding(totalWritten: Long): ByteArray {
        val numberOfBlocks = ((totalWritten + 8) / chunkSize) + 1
        val totalWrittenBits = totalWritten * 8
        return ByteArray(((numberOfBlocks * chunkSize) - totalWritten).toInt()).apply {
            this[0] = 0x80.toByte()
            for (i in 0 until 8) this[this.size - 8 + i] = (totalWrittenBits ushr (8 * i)).toByte()
        }
    }

    protected abstract fun core(chunk: ByteArray)
    protected abstract fun digestCore(out: ByteArray)
}

fun Hash.update(data: ByteArray) = update(data, 0, data.size)
fun Hash.digest(): ByteArray = ByteArray(digestSize).also { digest(it) }

fun <T : Hash> HashProvider<T>.digest(data: ByteArray) = create().also { it.update(data, 0, data.size) }.digest()
