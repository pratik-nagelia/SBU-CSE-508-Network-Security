package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"strings"
)

var (
	handle      *pcap.Handle
	err         error
	device      string
	snapshotLen int32 = 1600
	promiscuous       = true
)

func main() {
	//Input Command line arguments
	inputDevice := flag.String("i", "", "a string")
	inputFile := flag.String("r", "", "a string")
	key := flag.String("s", "", "a string")

	flag.Parse()
	filter := strings.Join(flag.Args(), " ")

	// First check if read from file flag is present
	if *inputFile != "" {
		handle, err = pcap.OpenOffline(*inputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	} else {
		// Check if input device is provided
		device = *inputDevice
		if device == "" {
			// If not present, then fall back to default device which is the first device
			device = firstDevice()
			log.Println("No custom input source provided. Choosing default network interface : ", device)
		} else if !deviceExists(device) {
			// Checking above if input device is valid
			log.Fatal("Unable to find network device :", *inputDevice)
		}
		handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	}

	setBPFFilter(filter)
	//Iterate over all packets and print them
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if payloadContainsKey(*key, packet) {
			printPacketInfo(packet)
		}
	}
}

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

func firstDevice() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		if device.Addresses != nil {
			return device.Name
		}
	}
	return ""
}

func payloadContainsKey(key string, packet gopacket.Packet) bool {
	var result = false
	if key == "" {
		return true
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		result = checkIfStringContains(udp.Payload, key)
	} else if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		result = checkIfStringContains(tcp.Payload, key)
	}
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		result = checkIfStringContains(ip.Payload, key)
	}
	return result
}

func checkIfStringContains(app []byte, key string) bool {
	if strings.Contains(string(app), key) {
		return true
	} else {
		return false
	}
}

func setBPFFilter(filter string) {
	//Applying BPF Filter to filter packets
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatal(err)
		}
	}
}

func printPacketInfo(packet gopacket.Packet) {
	fmt.Print(packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000"), " ")

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Print(ethernetPacket.SrcMAC, " -> ", ethernetPacket.DstMAC)
		fmt.Printf(" type %#0x ", uint16(ethernetPacket.EthernetType))
		fmt.Printf("len %d ", packet.Metadata().Length)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if tcpLayer != nil {
				printTCPInfo(packet, ip)
			} else if udpLayer != nil {
				printUDPInfo(packet, ip)
			} else {
				printOthers(ip)
			}
		}

		fmt.Println()
		fmt.Printf("%s", hex.Dump(ethernetPacket.Payload))
	}
	fmt.Println()
}

func printOthers(ip *layers.IPv4) {
	fmt.Printf("%s -> %s ", ip.SrcIP, ip.DstIP)
	fmt.Print(ip.Protocol, " ")
}

func printUDPInfo(packet gopacket.Packet, ip *layers.IPv4) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("%s:%d -> %s:%d ", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
		fmt.Print(ip.Protocol, " ")
	}
}

func printTCPInfo(packet gopacket.Packet, ip *layers.IPv4) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("%s:%d -> %s:%d ", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
		fmt.Print(ip.Protocol, " ")
		printTcpFlags(tcp)
	}
}

func printTcpFlags(tcp *layers.TCP) {
	if tcp.FIN {
		fmt.Print("FIN ")
	}
	if tcp.SYN {
		fmt.Print("SYN ")
	}
	if tcp.RST {
		fmt.Print("RST ")
	}
	if tcp.PSH {
		fmt.Print("PSH ")
	}
	if tcp.ACK {
		fmt.Print("ACK ")
	}
	if tcp.URG {
		fmt.Print("URG ")
	}
	if tcp.ECE {
		fmt.Print("ECE ")
	}
	if tcp.CWR {
		fmt.Print("CWR ")
	}
	if tcp.NS {
		fmt.Print("NS ")
	}
}
