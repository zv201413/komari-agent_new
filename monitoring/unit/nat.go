package monitoring

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

var (
	natTypeOnce   sync.Once
	cachedNat     = "检测中 (Detecting...)"
	OnNatDetected func(string)
)

// GetNatType returns the cached NAT type, triggering detection on first call
func GetNatType() string {
	natTypeOnce.Do(func() {
		go detectNatType()
	})
	return cachedNat
}

func detectNatType() {
	cachedNat = runNatDetection()
	log.Printf("[NAT] 检测完成。结果: %s", cachedNat)
	if OnNatDetected != nil {
		OnNatDetected(cachedNat)
	}
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return localAddr.IP.String()
}

func runNatDetection() string {
	lip := getLocalIP()
	if lip == "" {
		return "未知 (无法获取本地 IP)"
	}

	serverA := "stun.l.google.com:19302"
	serverB := "stun1.l.google.com:19302"

	addrA, err := net.ResolveUDPAddr("udp", serverA)
	if err != nil {
		return "未知 (DNS 解析失败)"
	}
	addrB, err := net.ResolveUDPAddr("udp", serverB)
	if err != nil {
		addrB = addrA
	}

	laddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return "未知 (创建 UDP 失败)"
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return "未知 (监听 UDP 失败)"
	}
	defer conn.Close()

	lport := conn.LocalAddr().(*net.UDPAddr).Port

	// Test 1: Send Binding Request to Server A
	m1, err := stunReq(conn, addrA, false, false)
	if err != nil {
		return "UDP 屏蔽 (Blocked)"
	}

	eip := m1.IP.String()
	eport := m1.Port

	if eip == lip && eport == lport {
		return "公网 IP (No NAT)"
	}

	// Test 2: Send Binding Request to Server A with Change IP & Port flags
	mc, err := stunReq(conn, addrA, true, true)
	if err == nil && mc != nil {
		return "全锥型 (Full Cone)"
	}

	// Test 3: Send Binding Request to Server B
	m2, err := stunReq(conn, addrB, false, false)
	if err != nil {
		return "未知 (限制型，Server B 无响应)"
	}

	if eip != m2.IP.String() || eport != m2.Port {
		return "对称型 (Symmetric NAT)"
	}

	// Test 4: Send Binding Request to Server A with Change Port flag
	mcp, err := stunReq(conn, addrA, false, true)
	if err == nil && mcp != nil {
		return "地址限制型 (Restricted Cone)"
	}

	return "端口限制型 (Port Restricted Cone)"
}

func stunReq(conn *net.UDPConn, serverAddr *net.UDPAddr, changeIP, changePort bool) (*net.UDPAddr, error) {
	var attrs []byte
	if changeIP || changePort {
		var f uint32
		if changeIP {
			f |= 0x04
		}
		if changePort {
			f |= 0x02
		}
		attrHeader := make([]byte, 8)
		binary.BigEndian.PutUint16(attrHeader[0:2], 0x0003) // CHANGE-REQUEST
		binary.BigEndian.PutUint16(attrHeader[2:4], 4)      // Length 4
		binary.BigEndian.PutUint32(attrHeader[4:8], f)
		attrs = attrHeader
	}

	tid := make([]byte, 12)
	_, _ = rand.Read(tid)

	pkt := make([]byte, 20+len(attrs))
	binary.BigEndian.PutUint16(pkt[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442) // Magic Cookie
	copy(pkt[8:20], tid)
	if len(attrs) > 0 {
		copy(pkt[20:], attrs)
	}

	_, err := conn.WriteTo(pkt, serverAddr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	if n < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	magic := binary.BigEndian.Uint32(buf[4:8])
	if magic != 0x2112A442 {
		return nil, fmt.Errorf("invalid magic cookie")
	}

	msgLen := binary.BigEndian.Uint16(buf[2:4])
	end := 20 + int(msgLen)
	if end > n {
		end = n
	}

	pos := 20
	for pos+4 <= end {
		at := binary.BigEndian.Uint16(buf[pos : pos+2])
		al := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
		pos += 4
		if pos+al > end {
			break
		}

		attrVal := buf[pos : pos+al]
		// Align to 4 bytes boundary
		pos += (al + 3) &^ 3

		// Type 0x0020: XOR-MAPPED-ADDRESS
		if at == 0x0020 && al >= 8 {
			family := attrVal[1]
			if family == 0x01 { // IPv4
				xport := binary.BigEndian.Uint16(attrVal[2:4])
				port := xport ^ uint16(0x2112A442>>16)
				xip := binary.BigEndian.Uint32(attrVal[4:8])
				ip := xip ^ 0x2112A442
				ipBytes := make([]byte, 4)
				binary.BigEndian.PutUint32(ipBytes, ip)
				return &net.UDPAddr{
					IP:   net.IP(ipBytes),
					Port: int(port),
				}, nil
			}
		}

		// Type 0x0001: MAPPED-ADDRESS
		if at == 0x0001 && al >= 8 {
			family := attrVal[1]
			if family == 0x01 { // IPv4
				port := binary.BigEndian.Uint16(attrVal[2:4])
				ip := net.IP(attrVal[4:8])
				return &net.UDPAddr{
					IP:   ip,
					Port: int(port),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no mapped address found")
}
