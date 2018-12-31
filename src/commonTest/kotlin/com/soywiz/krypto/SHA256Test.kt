package com.soywiz.krypto

import kotlin.test.Test
import kotlin.test.assertEquals

class SHA256Test {
    @Test
    fun test() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA256.digest(byteArrayOf()).hex)
        assertEquals("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", SHA256.digest("The quick brown fox jumps over the lazy dog".toByteArray()).hex)
        assertEquals("539deb4a951195ca3377514b8a44b95061b4fcd5ae21b29be3748cc835992b52", SHA256.digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".toByteArray()).hex)
    }
}