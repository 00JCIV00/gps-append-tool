/*
Author:     Jake Crawford
Created:    06 JUL 2022
Updated:    09 JUL 2022
Version:	0.0.3a

Details:	Append GPS data to survey files
 */

import com.github.ajalt.clikt.core.*
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.validate
import pcap.codec.ethernet.Ethernet
import pcap.codec.ip.Ip4
import pcap.codec.ip.Ip6
import pcap.codec.tcp.Tcp
import pcap.codec.udp.Udp
import pcap.spi.PacketBuffer
import pcap.spi.PacketHeader
import pcap.spi.Service
import pcap.spi.exception.ErrorException
import pcap.spi.exception.error.BreakException
import pcap.spi.option.DefaultOfflineOptions



class GAT: CliktCommand("GPS Append Tool.") {
	// Options
	val verbose by option("-v", help = "Enable verbose messaging.").flag("--no-verbose", default = false, defaultForHelp = "disabled")

	// Config
	val config by findOrSetObject { mutableMapOf<String, Any>() }

	override fun run(){
		config["verbose"] = verbose
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

	lateinit var filetype: String

	lateinit var output: String


	override fun run() {
		// Validation
		if(input.isNullOrEmpty()) {
			echo("--input file must be specified.")
			return
		}

		if(gpsData.isNullOrEmpty()) {
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
		if (config["verbose"] as Boolean) {
			for (item in listOf(input, gpsData, filetype, output)) {
				echo(item)
			}
		}
		else
			echo("Verbose mode off.")

		val pcapService = Service.Creator.create("PcapService")
		val pcapIn = pcapService.offline(input, DefaultOfflineOptions())
		try {
			var count = 0
			pcapIn.loop(
				1000,
				{ args: String, header: PacketHeader, buffer: PacketBuffer ->
					// echo("Args:\t$args")
					if (count % 1 == 0) {
						echo(count)
						echo("Header:\t${header}")
						echo("Packet:\t$buffer")
						val ethernet: Ethernet = buffer.cast(Ethernet::class.java)
						echo(ethernet)
						if (ethernet.type() == Ip4.TYPE) {
							val ip4: Ip4 = buffer.readerIndex(ethernet.size().toLong()).cast(Ip4::class.java)
							echo(ip4)
							if (ip4.protocol() == Tcp.TYPE) {
								val tcp: Tcp = buffer.readerIndex((ethernet.size() + ip4.size()).toLong()).cast(Tcp::class.java)
								echo(tcp)
							}
							else if (ip4.protocol() == Udp.TYPE) {
								val udp: Udp = buffer.readerIndex((ethernet.size() + ip4.size()).toLong()).cast(Udp::class.java)
								echo(udp)
							}
						}
						else if (ethernet.type() == Ip6.TYPE) {
							val ip6: Ip6 = buffer.readerIndex(ethernet.size().toLong()).cast(Ip6::class.java)
							echo(ip6)
							if (ip6.nextHeader() == Tcp.TYPE) {
								val tcp: Tcp = buffer.readerIndex((ethernet.size() + ip6.size()).toLong()).cast(Tcp::class.java)
								echo(tcp)
							}
							else if (ip6.nextHeader() == Udp.TYPE) {
								val udp: Udp = buffer.readerIndex((ethernet.size() + ip6.size()).toLong()).cast(Udp::class.java)
								echo(udp)
							}
						}
					}
					count++
				},
				"Test PCAP"
			)
		}
		catch (e: Exception) {
			when(e) {
				is BreakException, is ErrorException -> echo(err = true, message = e.message ?: "")
			}

		}
		pcapIn.close()
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
