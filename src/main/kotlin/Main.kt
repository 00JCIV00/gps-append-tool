/*
Author:     Jake Crawford
Created:    06 JUL 2022
Updated:    12 JUL 2022
Version:	0.0.4a

Details:	Append GPS data to survey files
 */

import com.github.ajalt.clikt.core.*
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.int
import com.silabs.na.pcap.Block
import com.silabs.na.pcap.IPcapInput
import com.silabs.na.pcap.PacketBlock
import com.silabs.na.pcap.Pcap

import com.savagej.pcap.PcapData
import com.savagej.pcap.kismet.KismetGPSData

import java.io.File
import java.text.DecimalFormat
import java.util.*


class GAT: CliktCommand("GPS Append Tool.") {
	// Options
	val verbosity by option("-v", help = "Set verbosity level (0-4) for messaging. 0 is lowest, 4 is highest.").int().default(0)
		.check("Verbosity must be between 0-4") { it in 0..4 }

	// Config
	val config by findOrSetObject { mutableMapOf<String, Any>() }

	override fun run(){
		config["verbosity"] = verbosity
	}
}

class Append: CliktCommand("Append GPS data from gps file to pcap file.") {
	// GAT Options
	val config by requireObject<Map<String, Any>>()

	// Options
	val filetypeOpt: String? by option("-f", "--filetype", help = "Specify the filetype of the input and output survey files. (Defaults to the filetype of the input file or '.pcap' failing that.)")

	val gpsData: String? by option("-g", "--gpsdata", help = "Specify the file containing GPS data.").
		validate {require(it.isNotEmpty()){"--gpsdata file must be specified."} }

	val input: String? by option("-i", "--input", help = "Specify the survey file to append GPS data onto.").
		validate {require(it.isNotEmpty()){"--input file must be specified."} }

	val outputOpt: String? by option("-o", "--output", help = "Specify the name of the output file for the new survey file with appended GPS data. (Defaults to the input filename with '_gps' appended before the filetype.)")

	val numPackets by option("-n", help = "[Debugging] Number of Packets to append to from input pcap file. (Defaults to 0 for all packets.)").int().default(0)

	lateinit var filetype: String

	lateinit var output: String


	override fun run() {
		// Validation
		if (input.isNullOrEmpty()) {
			echo("--input file must be specified.")
			return
		}

		if (gpsData.isNullOrEmpty()) {
			echo("--gpsdata file must be specified.")
			return
		}

		val inputSplit = input!!.split('.')

		filetype = if(filetypeOpt.isNullOrEmpty() && inputSplit.size > 1) {
			".${inputSplit.last()}"
		}
		else (if(!filetypeOpt.isNullOrEmpty()) filetypeOpt else ".pcap").toString()

		output = if(outputOpt.isNullOrEmpty()) {
			 "${inputSplit.subList(0, inputSplit.lastIndex).joinToString(".")}_gps$filetype"
		}
		else outputOpt.toString()


		// Logic
		val verbosity = config["verbosity"] as Int
		echo("\nVerbosity Level: $verbosity")
		if (verbosity >= 4) {
			for (item in listOf(input, gpsData, filetype, output)) {
				echo(item)
			}
		}

		echo("\n=============================\n")
		echo("Attempting to read in '$input'...")
		val pcapFileIn = File(input)

		try {
			// Pcap
			val pcapIn: IPcapInput = Pcap.openForReading(pcapFileIn)
			var curBlock = 0
			val countExp: () -> Boolean = if (numPackets > 0) { { curBlock < numPackets } } else { { true } }

			// - Kismet
			var foundKismetGPS = false
			val kismetGPSBlocks: MutableList<Pair<Int, Pair<Int, String>>> = mutableListOf()

			if (verbosity >= 1) echo("Checking for Kismet GPS Blocks...")
			while (countExp()) {
				val block: Block = pcapIn.nextBlock() ?: break
				if (verbosity >= 3) {
					echo("Block #: $curBlock\n===")
					echo("- Type: ${block.type()?.toString()}")
					echo("- Code:\n\tBin: ${Integer.toBinaryString(block.type()?.typeCode() ?: 0).padStart(8, '0')}b" +
								"\tDec: ${block.type()?.typeCode()}" +
								"\tHex: 0x${Integer.toHexString(block.type()?.typeCode() ?: 0).padStart(Int.SIZE_BYTES, '0').uppercase(Locale.getDefault())}")
				}
				// Custom Block - Kismet GPS
				if (block.type()?.typeCode() == 0x00000BAD) {
					if (verbosity >= 2) echo("***Found Kismet GPS Custom BLOCK!*** (Block: $curBlock)")
					kismetGPSBlocks.add(Pair(curBlock, Pair(1, "GPS Data:\t(WIP)")))
				}
				// Enhanced Packet Block
				else if (block.containsDataOfType(PacketBlock::class.java)) {
					// Custom Option - Kismet GPS
					block.options()?.forEachIndexed() { index, option ->
						// Detect Custom Option code
						if (option.code() == 2989) {
							val optionUInts = PcapData.extractUInts(option.value())
							val optionInternalHeader = PcapData.splitUInt(optionUInts[1], mutableListOf(8, 8, 16))
							if (verbosity >= 2) echo("- Option Internal Header:\n\t${Integer.toBinaryString(optionUInts[1].toInt()).padStart(32, '0')}" +
																						"\t${optionInternalHeader[0]}" +
																						"\t${optionInternalHeader[1]}" +
																						"\t${optionInternalHeader[2]}")
							// Detect Kismet GPS Magic Number
							if (optionInternalHeader.contains(0x47u)) {
								val uintCount: Int = if (optionUInts.size <= 20) optionUInts.size - 1 else 19
								for (i in 0..uintCount) {
									echo("$i: ${Integer.toBinaryString(optionUInts[i].toInt()).padStart(32, '0')}")
								}

								if (verbosity >= 2) echo("***Found Kismet GPS Custom Block Option!*** (Option: $index)")
								// Extract GPS
								val gpsData = "\tLat:${DecimalFormat("000.000000").format(KismetGPSData.decodeLat(optionUInts[2]))}  "

								kismetGPSBlocks.add(Pair(curBlock, Pair(index, "GPS Data: $gpsData")))
								foundKismetGPS = true
							}
						}
					}

					/*echo(" - Body (Raw):")
					echo("###: _______|_______|_______|_______|")
					val rawData = (block?.data() as PacketBlock).data() as ByteArray
					var bodyData: MutableList<UInt> = mutableListOf()
					for (i in 0..rawData.size step 4 ) {
						try {
							val index32: Int = i / 4
							// ID Common Byte Groups
							// - 32
							var int32: UInt = 0u
							for (j in 0..3) int32 += rawData[i + j].toUByte().toUInt() shl (8 * j)
							val bin32: String = Integer.toBinaryString(int32.toInt()).padStart(32, '0')
							bodyData.add(int32)
							if (config["superVerbose"] as Boolean) echo("${index32.toString().padStart(3, '0')}: $bin32")

							// - 16
							var int16one: UInt = 0u
							for (j in 0..1) int16one += rawData[i + j].toUByte().toUInt() shl (8 * j)
							var int16two: UInt = 0u
							for (j in 2..3) int16two += rawData[i + j].toUByte().toUInt() shl (8 * j)

							// ID Rover GPS Option in EPB
							if (int32 == 55922u || int16one == 0x47u) {
								echo("***Found Kismet GPS Custom Block Option!*** (Line: $index32)")
								kismetGPSBlocks.add(Pair(curBlock, Pair(index32, Integer.toBinaryString(int32.toInt()).padStart(32, '0'))))
								foundKismetGPS = true
							}
						}
						catch (e: ArrayIndexOutOfBoundsException) { break }
					}*/
				}
				else echo("- Data:\n${block.data()}")
				if (verbosity >= 2) echo("===\n")
				curBlock++
			}
			echo("Checked for Kismet GPS Data.")
			if (foundKismetGPS) {
				echo("Found Kismet GPS Data:")
				kismetGPSBlocks.forEach { echo(it) }
			}
			else echo("No Kismet GPS Data found.")

		}

		catch (e: Exception) {
			echo(err = true, message = "Error: ${e.cause}:\n${e.message}\n${e.stackTraceToString()}")
		}

		echo("\n\nAttempted to read in '$input'.\n")
	}

}

class Record: CliktCommand("Record GPS data from source to file") {
	// Options

	// Logic
	override fun run() {
		TODO("Recording GPS is not yet implemented.")
	}
}

fun main(args: Array<String>) {
	GAT().subcommands(Append(), Record()).main(args)
}
