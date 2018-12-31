package com.soywiz.krypto

import kotlin.test.Test
import kotlin.test.assertEquals

class MD5Test {
    @Test
    fun test() {
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", MD5.digest("".toByteArray()).hex)
        assertEquals("0cc175b9c0f1b6a831c399e269772661", MD5.digest("a".toByteArray()).hex)
        assertEquals("900150983cd24fb0d6963f7d28e17f72", MD5.digest("abc".toByteArray()).hex)
        assertEquals("f96b697d7cb7938d525a2f31aaf161d0", MD5.digest("message digest".toByteArray()).hex)
        assertEquals("c3fcd3d76192e4007dfb496cca67e13b", MD5.digest("abcdefghijklmnopqrstuvwxyz".toByteArray()).hex)
        assertEquals("d174ab98d277d9f5a5611c2c9f419d9f", MD5.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArray()).hex)
        assertEquals("57edf4a22be3c955ac49da2e2107b67a", MD5.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".toByteArray()).hex)
    }
}