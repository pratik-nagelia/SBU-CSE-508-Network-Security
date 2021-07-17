package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

var (
	pwd      string
	bufferSize = 4096
)

func main() {
	//Input Command line arguments
	listenPort := flag.Int("l", -1, "an int")
	pwdfile := flag.String("p", "", "a string")

	flag.Parse()
	if len(flag.Args()) < 2 {
		log.Fatal("Missing Destination IP or Port:")
	}

	if *pwdfile == "" {
		log.Fatal("Missing password file input")
	}

	destination := flag.Args()[0]
	dstPort := flag.Args()[1]
	if destination == "" || dstPort == "" {
		log.Fatal("Missing Destination IP or Port:")
	}

	pwd = readPwdFromFile(*pwdfile)

	if *listenPort == -1 {
		forwardProxyMode(destination, dstPort)
	} else {
		reverseProxyMode(getLocalIP(), *listenPort, destination, dstPort)
	}

}

func forwardProxyMode(destination string, dstPort string) {
	dstAddr := fmt.Sprintf("%s:%s", destination, dstPort)
	dstConn, err := net.Dial("tcp", dstAddr)
	if err != nil {
		log.Printf("Can't connect to destination server: %s\n", err)
		return
	}
	go readFromForwardProxy(dstConn)

	tmp := make([]byte, bufferSize)
	for {
		n, err := os.Stdin.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		encryptedData := encrypt(pwd, string(tmp[:n]))
		dstConn.Write([]byte(encryptedData))
	}
}

func readFromForwardProxy(dstConn net.Conn) {
	tmp := make([]byte, bufferSize)
	for {
		n, err := dstConn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		decryptedString := decrypt(pwd, string(tmp[:n]))
		os.Stdout.Write([]byte(decryptedString))
	}
}

func reverseProxyMode(host string, listenPort int, destination string, dstPort string) {
	addr := fmt.Sprintf("%s:%d", host, listenPort)
	listener, err := net.Listen("tcp", addr)

	if err != nil {
		panic(err)
	}
	log.Printf("Listening for connections on %s", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection from client: %s", err)
		} else {
			go handshakeWithServer(conn, destination+":"+dstPort)
		}
	}
}

func handshakeWithServer(sourceConn net.Conn, addr string) {
	dstConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Can't connect to server: %s\n", err)
		return
	}

	go readFromReverseProxy(sourceConn, dstConn)

	tmp := make([]byte, bufferSize)
	for {
		n, err := sourceConn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				log.Println("read error:", err)
			}
			break
		}
		decryptedString := decrypt(pwd, string(tmp[:n]))
		dstConn.Write([]byte(decryptedString))
	}
}

func readFromReverseProxy(srcConn net.Conn, dstConn net.Conn) {

	tmp := make([]byte, bufferSize)
	for {
		n, err := dstConn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				log.Println("read error:", err)
			}
			break
		}
		encryptedData := encrypt(pwd, string(tmp[:n]))
		srcConn.Write([]byte(encryptedData))
		//srcConn.Write(tmp[:n])
	}

}

func readPwdFromFile(path string) string {
	var pwd string
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pwd += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return pwd
}

func getLocalIP() string {
	var localIp string
	localIp = "127.0.0.1"
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		if device.Addresses != nil {
			localIp = device.Addresses[0].IP.String()
			if localIp != "" && strings.Contains(localIp, ":") {
				localIp = device.Addresses[1].IP.String()
			}
			break
		}
	}
	return localIp
}

func deriveKey(passphrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passphrase), salt, 1000, 32, sha256.New), salt
}

func encrypt(passphrase, plaintext string) string {
	key, salt := deriveKey(passphrase, nil)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	data := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(nonce) + "-" + hex.EncodeToString(data)
}

func decrypt(passphrase, ciphertext string) string {
	arr := strings.Split(ciphertext, "-")
	salt, _ := hex.DecodeString(arr[0])
	nonce, _ := hex.DecodeString(arr[1])
	data, _ := hex.DecodeString(arr[2])
	key, _ := deriveKey(passphrase, salt)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	data, _ = aesgcm.Open(nil, nonce, data, nil)
	return string(data)
}