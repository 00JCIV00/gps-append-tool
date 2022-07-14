/*
Author:     Jake Crawford
Created:    06 JUL 2022
Updated:    13 JUL 2022
Version:	0.0.5a

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
import com.silabs.na.pcap.OtherBlock

import java.io.File
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
					val blockUInts = PcapData.formatToUInts((block.data() as OtherBlock).body())
					if (verbosity >= 2) {
						echo("***Found Kismet GPS Custom BLOCK!*** (Block: $curBlock)")
						val uintCount: Int = if (blockUInts.size <= 20) blockUInts.size - 1 else 19
						echo ("- 32 Bit Lines:")
						for (i in 0..uintCount) echo("$i: ${Integer.toBinaryString(blockUInts[i].toInt()).padStart(32, '0')}")
					}
					// Extract GPS
					val gpsData = KismetGPSData.mapGPSData(blockUInts[2], blockUInts.subList(3, blockUInts.size))
					kismetGPSBlocks.add(Pair(curBlock, Pair(0, "GPS Block:\t$gpsData")))
				}
				// Enhanced Packet Block
				else if (block.containsDataOfType(PacketBlock::class.java)) {
					// Custom Option - Kismet GPS
					block.options()?.forEachIndexed() { index, option ->
						// Detect Custom Option code
						if (option.code() == 2989) {
							val optionUInts = PcapData.formatToUInts(option.value())
							val optionInternalHeader = PcapData.splitUInt(optionUInts[1], mutableListOf(8, 8, 16))
							if (verbosity >= 2) echo("- Option\n-- Internal Header:\n\t${Integer.toBinaryString(optionUInts[1].toInt()).padStart(32, '0')}" +
																						"\t${optionInternalHeader[0]}" +
																						"\t${optionInternalHeader[1]}" +
																						"\t${optionInternalHeader[2]}")
							// Detect Kismet GPS Magic Number
							if (optionInternalHeader.contains(0x47u)) {
								if (verbosity >= 2){
									val uintCount: Int = if (optionUInts.size <= 20) optionUInts.size - 1 else 19
									echo ("-- 32 Bit Lines:")
									for (i in 0..uintCount) echo("$i: ${Integer.toBinaryString(optionUInts[i].toInt()).padStart(32, '0')}")
									echo("***Found Kismet GPS Custom Block Option!*** (Option: $index)")
									echo("-- GPS Fields: ${KismetGPSData.checkGPSFields(optionUInts[2])}")
								}
								// Extract GPS
								val gpsData = KismetGPSData.mapGPSData(optionUInts[2], optionUInts.subList(3, optionUInts.size))

								kismetGPSBlocks.add(Pair(curBlock, Pair(index, "GPS Option:\t$gpsData")))
								foundKismetGPS = true
							}
						}
					}
				}
				else if (verbosity >= 2) {
					echo("- Data:\n${block.data()}")
					echo("===\n")
				}
				curBlock++
			}
			echo("Checked for Kismet GPS Data.")
			if (foundKismetGPS) {
				echo("Found Kismet GPS Data:")
				kismetGPSBlocks.forEach { echo("Block: ${it.first.toString().padStart(6, '0')}, Option: ${it.second.first}, Data:\t${it.second.second}") }
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
