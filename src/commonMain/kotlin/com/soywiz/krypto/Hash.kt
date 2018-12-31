package com.soywiz.krypto

import com.soywiz.krypto.internal.arraycopy
import kotlin.math.min

open class HashFactory(val create: () -> Hash) {
    fun digest(data: ByteArray) = create().also { it.update(data, 0, data.size) }.digest()
}

abstract class Hash(val chunkSize: Int, val digestSize: Int) {
    private val chunk = ByteArray(chunkSize)
    private var writtenInChunk = 0
    private var totalWritten = 0L

    protected abstract fun reset(): Hash

    fun update(data: ByteArray, offset: Int, count: Int): Hash {
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

    fun digestOut(out: ByteArray) {
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

    protected abstract fun generatePadding(totalWritten: Long): ByteArray
    protected abstract fun core(chunk: ByteArray)
    protected abstract fun digestCore(out: ByteArray)

    fun update(data: ByteArray) = update(data, 0, data.size)
    fun digest(): ByteArray = ByteArray(digestSize).also { digestOut(it) }
}
