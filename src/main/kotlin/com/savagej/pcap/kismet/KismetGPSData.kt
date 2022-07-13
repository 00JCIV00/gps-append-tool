/*
Author:     Jake Crawford
Created:    12 JUL 2022
Updated:    12 JUL 2022
Version:	0.0.4a

Details:	Encode and Decode custom pcap-ng bytes to and from Kismet gps data
 */

package com.savagej.pcap.kismet

class KismetGPSData {
	companion object {
		/**
		 * Returns the decoded latitude of a Kismet-style 32 bit [rawUInt] with 3_6 (###.######) precision.
		 */
		fun decodeLat(rawUInt: UInt): Float {
			val max = 1000000000u
			if (rawUInt > max) throw KismetPcapException(craftException("decode", "latitude", rawUInt, max))
			return rawUInt.toFloat() / 1000000.0f
		}

		/**
		 * Returns the decoded longitude of a Kismet-style 32 bit [rawUInt] with 3_7 (###.#######) precision.
		 */
		fun decodeLong(rawUInt: UInt): Float {
			val max = 3600000000u
			if (rawUInt > max) throw KismetPcapException(craftException("decode", "longitude", rawUInt, max))
			return (rawUInt.toFloat() - (180 * 1000000.0f)) / 1000000.0f
		}

		/**
		 * Returns Exception String for Decodes.
		 */
		fun craftException(operation: String, type: String, value: Any, max: Any, min: Any = 0u): String {
			return "Unable to $operation $type from value: $value. The value must be within $min to $max."
		}
	}
}

class KismetPcapException(message: String): Exception(message)