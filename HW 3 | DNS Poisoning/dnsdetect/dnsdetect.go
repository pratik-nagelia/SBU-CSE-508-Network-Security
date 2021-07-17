package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	handle      *pcap.Handle
	err         error
	device      string
	macAddress  net.HardwareAddr
	dnsMap      map[uint16]DnsMsg
	snapshotLen int32 = 1024
	promiscuous       = true
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions
	mutex = &sync.Mutex{}
)

type DnsMsg struct {
	Timestamp     time.Time
	TransactionId uint16
	DnsName       string
	IpAddresses   []string
}


func main() {
	dnsMap= make(map[uint16]DnsMsg)

	//Input Command line arguments
	inputDevice := flag.String("i", "", "a string")
	inputFile := flag.String("r", "", "a string")

	flag.Parse()
	filter := strings.Join(flag.Args(), " ")

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
		if isDNSPacket(packet) {
			go evictData(packet.Metadata().Timestamp)
			mutex.Lock()
			dnsMsg, ok := dnsMap[getTransactionId(packet)]
			mutex.Unlock()
			if  ok {
				printAttempt(packet, dnsMsg)
			} else {
				data := getDnsMsg(packet)
				mutex.Lock()
				dnsMap[data.TransactionId] = data
				mutex.Unlock()
			}
		}
	}
}

func getTransactionId(packet gopacket.Packet) uint16 {
	dnsRequest, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	return dnsRequest.ID
}

func printAttempt(packet gopacket.Packet, msg DnsMsg) {
	msg2 := getDnsMsg(packet)
	fmt.Println()
	fmt.Println(msg.Timestamp.String(), ":> DNS poisoning attempt")
	fmt.Println("TXID ", msg.TransactionId, " Request " , msg.DnsName)
	fmt.Println("Answer1 ", msg.IpAddresses)
	fmt.Println("Answer1 ", msg2.IpAddresses)
}

func getDnsMsg(packet gopacket.Packet) DnsMsg {

	dnsRequest, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)

	var ipAddresses []string

	for _, dnsAnswer := range dnsRequest.Answers {
		if dnsAnswer.IP != nil {
			ipAddresses = append(ipAddresses, dnsAnswer.IP.String())
		}
	}

	dnsMsg := DnsMsg{
		Timestamp:     packet.Metadata().Timestamp,
		TransactionId: getTransactionId(packet),
		DnsName:       string(dnsRequest.Questions[0].Name),
		IpAddresses:   ipAddresses,
	}
	return dnsMsg
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

func isDNSPacket(packet gopacket.Packet) bool {
	var result = false
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 53 {
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

func evictData(CurrTimestamp time.Time)  {
	if len(dnsMap)> 1000 {
		var txIds []uint16
		mutex.Lock()
		for key, value := range dnsMap {
			if value.Timestamp.Before(CurrTimestamp.Add(-30 * time.Second)) {
				txIds = append(txIds, key)
			}
		}
		mutex.Unlock()
		for key := range txIds {
			mutex.Lock()
			delete(dnsMap, uint16(key))
			mutex.Unlock()
		}
	}
}
