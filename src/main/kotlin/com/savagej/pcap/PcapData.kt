/*
Author:     Jake Crawford
Created:    12 JUL 2022
Updated:    12 JUL 2022
Version:	0.0.4a

Details:	Extract data from pcap file bytes
 */

package com.savagej.pcap

import kotlin.math.pow

class PcapData {
	companion object {
		/**
		 * Returns a List of UInts built from the given ByteArray [bytes]
		 */
		fun extractUInts(bytes: ByteArray): List<UInt> {
			val uints = buildList {
				for (i in 0..bytes.size step 4 ) {
					try {
						var uint: UInt = 0u
						for (j in 0..3) uint += bytes[i + j].toUByte().toUInt() shl (8 * j)
						add(uint)
					} catch (e: ArrayIndexOutOfBoundsException) {
						break
					}
				}
			}
			return uints
		}

		/**
		 * Returns a List of UInts derived from splitting a 32 bit UInt [source32] into smaller UInts of [bitLengths].
		 */
		fun splitUInt(source32: UInt, bitLengths: MutableList<Int>): List<UInt> {
			var base32 = source32
			if (bitLengths.sum() > 32) return emptyList()
			else if (bitLengths.sum() < 32) bitLengths.add(32 - bitLengths.size)
			val uints = buildList {
				bitLengths.forEach { bitLength ->
					add(base32 and (2.0.pow(bitLength) - 1).toUInt())
					base32 = base32 shr bitLength
				}
			}
			return uints
		}
	}
}