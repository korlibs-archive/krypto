package com.soywiz.krypto.internal

internal inline fun Int.ext8(offset: Int) = (this ushr offset) and 0xFF
