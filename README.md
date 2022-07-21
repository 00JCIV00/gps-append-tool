# gps-append-tool
- **Author:**     Jake Crawford
- **Created:**    06 JUL 2022
- **Updated:**    20 JUL 2022
- **Version:**    0.0.5a
- **GitHubLink:**     [gps-append-tool](https://github.com/00JCIV00/gps-append-tool)
- **Description:**    Append GPS data to survey files.

## Instructions
WIP

## Resources
### External Libraries
1. [Clikt](https://github.com/ajalt/clikt): Kotlin library to create Command Line Interfaces.
2. [java_pcap_file_utilities](https://github.com/SiliconLabs/java_pcap_file_utilities): Java library to manipulate pcapng data at the Block level.  
### Information
1. [Kismet pcapng docs](https://kismetwireless.net/docs/devel/pcapng-gps/): Kismet developer documentation detailing how Kismet adds GPS data to pcapng files via both Custom Blocks and Custom Options within Enhanced Packet Blocks.
2. [IETF pcapng docs](https://www.ietf.org/staging/draft-tuexen-opsawg-pcapng-02.html) Internet Engineering Task Force (IETF) documentation on the pcapng file format detailing how Blocks and Options are structured at the binary level.
3. [IETF pcap docs](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html) IETF documentation on the pcap file format detailing how File Headers and Packet Records are structured at the binary level.
4. [CACE Tech ppi spec](https://www.ikeriri.ne.jp/download/airpcap/PPI%20Header%20format%201.0.9.pdf) CACE Technologies Per-Packet Information (PPI) Header Specification detailing how PPI data is structured within pcap files at the binary level.