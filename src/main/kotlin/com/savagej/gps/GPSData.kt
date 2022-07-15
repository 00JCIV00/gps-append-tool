/*
Author:     Jake Crawford
Created:    14 JUL 2022
Updated:    14 JUL 2022
Version:	0.0.5a

Details:	Intermediary data class for GPS data.
 */

package com.savagej.gps

import java.util.*

/**
 * Intermediary data class for GPS data.
 */
data class GPSData(val lat: Float = 0f, val long: Float = 0f,
				   val alt: Float = 0f, val altG: Float = 0f,
				   val gpsTime: UInt = 0u, val gpsFracTime: UInt = 0u,
				   val eph: Float = 0f, val epv: Float = 0f,
				   val timestampHigh: UInt = 0u, val timestampLow: UInt = 0u,
				   val timestampEpoch: ULong = 0u.toULong()){

	/**
	 * Creates a GPSData object from the GPS Data in the provided Map [gpsMap].
	 */
	constructor(gpsMap: Map<String, Any?>):
		this((gpsMap["LATITUDE"] ?: 0f) as Float, (gpsMap["LONGITUDE"] ?: 0f) as Float,
			 (gpsMap["ALTITUDE"] ?: 0f) as Float, (gpsMap["ALTITUDE_G"] ?: 0f) as Float,
			 (gpsMap["GPS_TIME"] ?: 0u) as UInt, (gpsMap["GPS_FRACTIONAL_TIME"] ?: 0u) as UInt,
			 (gpsMap["EPH"] ?: 0f) as Float, (gpsMap["EPV"] ?: 0f) as Float,
			 (gpsMap["TIMESTAMP_HIGH"] ?: 0u) as UInt, (gpsMap["TIMESTAMP_LOW"] ?: 0u) as UInt,
			 (gpsMap["TIMESTAMP_EPOCH"] ?: 0u.toULong()) as ULong)

	val timestampDateTime = Date((timestampEpoch.toLong()) / 1000 )

	/**
	 * Returns Map of the GPSData object's properties
	 */
	fun toMap(): Map<String, Any> {
		return mapOf("LATITUDE" to lat, "LONGITUDE" to long,
					 "ALTITUDE" to alt, "ALTITUDE_G" to altG,
					 "GPS_TIME" to gpsTime, "GPS_FRACTIONAL_TIME" to gpsFracTime,
					 "EPH" to eph, "EPV" to epv,
					 "TIMESTAMP_HIGH" to timestampHigh, "TIMESTAMP_LOW" to timestampLow,
					 "TIMESTAMP_EPOCH" to timestampEpoch, "TIMESTAMP_DATETIME" to timestampDateTime)
	}
}

