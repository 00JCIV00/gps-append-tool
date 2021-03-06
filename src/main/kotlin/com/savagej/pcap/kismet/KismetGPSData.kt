/*
Author:     Jake Crawford
Created:    12 JUL 2022
Updated:    20 JUL 2022
Version:	0.0.5a

Details:	Encode and Decode custom pcap-ng bytes to and from Kismet gps data
 */

package com.savagej.pcap.kismet

import com.savagej.gps.GPSData
import com.savagej.pcap.PcapData
import java.util.Date

class KismetGPSData {
	companion object {
		/**
		 * Enumeration of all Kismet GPS Field Indeces.
		 */
		enum class KismetGPSFields(val index: UInt) {
			LONGITUDE(0x2u),
			LATITUDE(0x4u),
			ALTITUDE(0x8u),
			ALTITUDE_G(0x10u),
			GPS_TIME(0x20u),
			GPS_FRACTIONAL_TIME(0x40u),
			EPH(0x80u),
			EPV(0x100u),
			TIMESTAMP_HIGH(0x400u),
			TIMESTAMP_LOW(0x800u)
		}

		/**
		 * Returns a List of KismetGPSFields available based on the provided UInt [gpsFieldsBitmask].
		 */
		fun checkGPSFields(gpsFieldsBitmask: UInt): List<KismetGPSFields> {
			return KismetGPSFields.values().filter { field -> gpsFieldsBitmask and field.index == field.index }
		}

		/**
		 * Returns a GPSData object built from the provided UInt [gpsFieldsBitmask] and UInt List [gpsDataRaw].
		 */
		fun mapPcapngGPSData(gpsFieldsBitmask: UInt, gpsDataRaw: List<UInt>): GPSData {
			val gpsDataMap = buildMap {
				checkGPSFields(gpsFieldsBitmask).forEachIndexed() { index, field ->
					if(index < gpsDataRaw.size) {
						val gpsData = when (field.index) {
							KismetGPSFields.LONGITUDE.index, KismetGPSFields.LATITUDE.index -> decodeLatLong(gpsDataRaw[index])
							KismetGPSFields.ALTITUDE.index, KismetGPSFields.ALTITUDE_G.index, KismetGPSFields.EPH.index, KismetGPSFields.EPV.index -> decodeAlt(gpsDataRaw[index])
							KismetGPSFields.GPS_TIME.index, KismetGPSFields.GPS_FRACTIONAL_TIME.index, KismetGPSFields.TIMESTAMP_HIGH.index, KismetGPSFields.TIMESTAMP_LOW.index -> gpsDataRaw[index]
							else -> 0u
						}
						put(field.name, gpsData)
						if (field.name == "TIMESTAMP_LOW") {
							val timestamp = PcapData.decodeTimestampEpoch(this["TIMESTAMP_HIGH"] as UInt, this["TIMESTAMP_LOW"] as UInt)
							put("TIMESTAMP_EPOCH", timestamp["EPOCH_RAW_uS"])
							put("TIMESTAMP_DATETIME", Date((timestamp["EPOCH_RAW_uS"]?.toLong() ?: 1) / 1000 ))
						}
					}
				}
			}
			return GPSData(gpsDataMap)
		}

		/**
		 * Returns the decoded 3_6 of a Kismet-style 32 bit [rawUInt] with 3_6 (###.######) precision.
		 */
		fun decode3_6(rawUInt: UInt): Float {
			val max = 1000000000u
			if (rawUInt > max) throw KismetPcapException(craftCodeException("decode", "3_6", rawUInt, max))
			return rawUInt.toFloat() / 1000000.0f
		}

		/**
		 * Returns the decoded Latitude or Longitude of a Kismet-style 32 bit [rawUInt] with 3_7 (###.#######) precision.
		 */
		fun decodeLatLong(rawUInt: UInt): Float {
			val max = 3600000000u
			if (rawUInt > max) throw KismetPcapException(craftCodeException("decode", "latitude or longitude", rawUInt, max))
			return (rawUInt.toFloat() - (180 * 10000000)) / 10000000
		}

		/**
		 * Returns the decoded Altitude of a Kismet-style 32 bit [rawUInt] with 6_4 (######.####) precision.
		 */
		fun decodeAlt(rawUInt: UInt): Float {
			val max = 3600000000u
			if (rawUInt > max) throw KismetPcapException(craftCodeException("decode", "altitude", rawUInt, max))
			return (rawUInt.toFloat() - (180000  * 10000)) / 10000
		}

		/**
		 * Returns Exception String for Decodes.
		 */
		private fun craftCodeException(operation: String, type: String, value: Any, max: Any, min: Any = 0u): String {
			return "Unable to $operation $type from value: $value. The value must be within $min to $max."
		}
	}
}

class KismetPcapException(message: String): Exception(message)
