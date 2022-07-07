/*
Author:     Jake Crawford
Created:    06 July 2022
Updated:    06 July 2022
Version:	0.0.1a

Details:	Append GPS data to survey files
 */

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.validate


class GAT: CliktCommand(help = "GPS Append Tool.") {
	// Commands
	val filetype_opt: String? by option("-f", "--filetype", help = "Specify the filetype of the input and output survey files. (Defaults to the filetype of the input file or '.pcap' failing that.)")

	val gpsdata: String? by option("-g", "--gpsdata", help = "Specify the file containing GPS data.").
		validate {require(it.isNotEmpty()){"--gpsdata file must be specified."} }

	val input: String? by option("-i", "--input", help = "Specify the survey file to append GPS data onto.").
		validate {require(it.isNotEmpty()){"--input file must be specified."} }

	val output_opt: String? by option("-o", "--output", help = "Specify the name of the output file for the new survey file with appended GPS data. (Defaults to the input file name with '_gps' appended before the filetype.)")

	lateinit var filetype: String

	lateinit var output: String


	override fun run() {
		// Validation
		if(input.isNullOrEmpty()) {
			echo("--input file must be specified.")
			return
		}

		if(gpsdata.isNullOrEmpty()) {
			echo("--gpsdata file must be specified.")
			return
		}

		val inputSplit = input!!.split('.')

		if(filetype_opt.isNullOrEmpty() && inputSplit.size > 1) {
			filetype = ".${inputSplit.last()}"
		}
		else filetype = ".pcap"

		if(output_opt.isNullOrEmpty()) {
			output = "${inputSplit.subList(0, inputSplit.lastIndex).joinToString(".")}_gps$filetype"
		}

		// Logic
		for(item in listOf(input, gpsdata, filetype, output)){
			echo(item)
		}
	}

}

fun main(args: Array<String>) {
	GAT().main(args)
}
