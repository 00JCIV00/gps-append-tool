/*
Author:     Jake Crawford
Created:    12 JUL 2022
Updated:    14 JUL 2022
Version:	0.0.5a

Details:	Extract data from pcap file bytes
 */

package com.savagej.pcap

import kotlin.math.pow

class PcapData {
	companion object {
		/**
		 * Returns a List of UInts built from the given ByteArray [bytes]
		 */
		fun formatToUInts(bytes: ByteArray): List<UInt> {
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

		/**
		 * Returns a map of Epoch Microseconds Raw, Epoch Seconds, and Epoch Microseconds based on the provided ULong [timestamp].
		 */
		fun decodeTimestampEpoch(timestamp: ULong): Map<String, ULong> {
			val seconds = timestamp / 1000000u
			val microseconds = timestamp % 1000000u
			return mapOf("EPOCH_RAW_uS" to timestamp, "EPOCH_S" to seconds, "EPOCH_uS" to microseconds)
		}

		/**
		 * Returns a map of Epoch Microseconds Raw, Epoch Seconds, and Epoch Microseconds based on the provided UInts [timestampHigh] and [timestampLow].
		 */
		fun decodeTimestampEpoch(timestampHigh: UInt, timestampLow: UInt): Map<String, ULong> {
			return decodeTimestampEpoch(timestampHigh.toULong() shl 32 or timestampLow.toULong())
		}


	}
}
