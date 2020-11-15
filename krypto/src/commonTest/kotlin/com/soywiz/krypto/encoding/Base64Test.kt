package com.soywiz.krypto.encoding

import kotlin.test.Test
import kotlin.test.assertEquals

class Base64Test {

    @Test
    fun shouldEncodeStringToBase64UrlSafe() {
        val url = "aaa/test?&=a"
        val expectedSafe = "YWFhL3Rlc3Q_Jj1h"
        val actualSafe = ASCII(url).toBase64UrlSafe()

        val actualSafeWithVal = ASCII(url).base64UrlSafe

        assertEquals(expectedSafe, actualSafe)
        assertEquals(expectedSafe, actualSafeWithVal)
    }

    @Test
    fun shouldEncodeStringToBase64() {
        val url = "aaa/test?&=a"
        val expected = "YWFhL3Rlc3Q/Jj1h"
        val actual = ASCII(url).toBase64()

        val actualWithVal = ASCII(url).base64

        assertEquals(expected, actual)
        assertEquals(expected, actualWithVal)
    }

    @Test
    fun shouldDecodeBase64ToStringUrl() {
        val expectedSafe = "aaa/test?&=a"
        val actualSafe = ASCII("YWFhL3Rlc3Q_Jj1h".fromBase64UrlSafe())

        assertEquals(expectedSafe, actualSafe)
    }

    @Test
    fun shouldDecodeBase64ToString() {
        val expectedSafe = "aaa/test?&=a"
        val actualSafe = ASCII("YWFhL3Rlc3Q/Jj1h".fromBase64())

        assertEquals(expectedSafe, actualSafe)
    }

    @Test
    fun shouldDecodeBase64IgnoringSpaces() {
        val expectedSafe = "aaa/test?&=a"
        val actualSafe = ASCII("YWFh\nL3Rlc3Q/Jj1h".fromBase64IgnoreSpaces())

        assertEquals(expectedSafe, actualSafe)
    }

    @Test
    fun shouldDecodeBase64UrlIgnoringSpaces() {
        val expectedSafe = "aaa/test?&=a"
        val actualSafe = ASCII("YWFh\nL3Rlc3Q_Jj1h".fromBase64UrlSafeIgnoreSpaces())

        assertEquals(expectedSafe, actualSafe)
    }
}
