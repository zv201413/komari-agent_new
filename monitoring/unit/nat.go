package monitoring

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	natMu         sync.Mutex
	cachedNat     = "检测中 (Detecting...)"
	lastNatCheck  time.Time
	isDetecting   bool
	natExpiry     = 12 * time.Hour
	OnNatDetected func(string)
)

func GetNatType() string {
	natMu.Lock()
	defer natMu.Unlock()

	if lastNatCheck.IsZero() || time.Since(lastNatCheck) > natExpiry {
		if !isDetecting {
			isDetecting = true
			natMu.Unlock() // Unlock while blocking
			
			result := runNatDetection()
			
			natMu.Lock() // Relock to update
			cachedNat = result
			lastNatCheck = time.Now()
			isDetecting = false
			
			if OnNatDetected != nil {
				// Avoid holding lock during callback if it might block, though usually it's fast
				go OnNatDetected(result)
			}
		}
		return cachedNat
	}

	return cachedNat
}

func StartPeriodicNatDetection() {
	ticker := time.NewTicker(natExpiry)
	for range ticker.C {
		natMu.Lock()
		if !isDetecting {
			isDetecting = true
			natMu.Unlock()
			go func() {
				result := runNatDetection()
				natMu.Lock()
				cachedNat = result
				lastNatCheck = time.Now()
				isDetecting = false
				if OnNatDetected != nil {
					go OnNatDetected(result)
				}
				natMu.Unlock()
			}()
		} else {
			natMu.Unlock()
		}
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

var stunServers = []string{
	"stun.cloudflare.com:443",
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.voipbuster.com:3478",
}

func runNatDetection() string {
	lip := getLocalIP()
	if lip == "" {
		return "未知 (无法获取本地 IP)"
	}

	if !dnsProbe() {
		return "UDP 阻断 (UDP Blocked)"
	}

	var resolved []*net.UDPAddr
	for _, s := range stunServers {
		addr, err := net.ResolveUDPAddr("udp", s)
		if err == nil {
			resolved = append(resolved, addr)
		}
	}
	if len(resolved) == 0 {
		return "STUN 受限 (DNS 解析失败)"
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

	m1, m1Addr, err := stunReq(conn, resolved)
	if err != nil {
		return "STUN 受限 (STUN Blocked)"
	}

	eip := m1.IP.String()
	eport := m1.Port

	if eip == lip && eport == lport {
		return "公网 IP (No NAT)"
	}

	m2, err := stunReqDiff(conn, resolved, m1Addr)
	if err != nil {
		return "锥型 NAT (Cone NAT)"
	}

	if eip != m2.IP.String() || eport != m2.Port {
		return "对称型 (Symmetric NAT)"
	}

	return "锥型 NAT (Cone NAT)"
}

func dnsProbe() bool {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 53,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	pkt := []byte{
		0x00, 0x01,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(pkt)
	if err != nil {
		return false
	}

	buf := make([]byte, 512)
	_, err = conn.Read(buf)
	return err == nil
}

func stunReq(conn *net.UDPConn, addrs []*net.UDPAddr) (*net.UDPAddr, *net.UDPAddr, error) {
	tid := make([]byte, 12)
	_, _ = rand.Read(tid)

	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0001)
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442)
	copy(pkt[8:20], tid)

	for _, addr := range addrs {
		_, err := conn.WriteTo(pkt, addr)
		if err != nil {
			continue
		}

		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		mapped, err := parseStunResponse(buf[:n], tid)
		if err != nil {
			continue
		}
		return mapped, addr, nil
	}

	return nil, nil, fmt.Errorf("no STUN server responded")
}

func stunReqDiff(conn *net.UDPConn, addrs []*net.UDPAddr, exclude *net.UDPAddr) (*net.UDPAddr, error) {
	tid := make([]byte, 12)
	_, _ = rand.Read(tid)

	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0001)
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442)
	copy(pkt[8:20], tid)

	for _, addr := range addrs {
		if addr.IP.Equal(exclude.IP) {
			continue
		}
		_, err := conn.WriteTo(pkt, addr)
		if err != nil {
			continue
		}

		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		mapped, err := parseStunResponse(buf[:n], tid)
		if err != nil {
			continue
		}
		return mapped, nil
	}

	return nil, fmt.Errorf("no different-IP STUN server responded")
}

func parseStunResponse(buf []byte, tid []byte) (*net.UDPAddr, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	magic := binary.BigEndian.Uint32(buf[4:8])
	if magic != 0x2112A442 {
		return nil, fmt.Errorf("invalid magic cookie")
	}

	if len(buf) >= 20 {
		for i := 0; i < 12; i++ {
			if buf[8+i] != tid[i] {
				return nil, fmt.Errorf("transaction ID mismatch")
			}
		}
	}

	msgLen := binary.BigEndian.Uint16(buf[2:4])
	end := 20 + int(msgLen)
	if end > len(buf) {
		end = len(buf)
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
		pos += (al + 3) &^ 3

		if at == 0x0020 && al >= 8 {
			family := attrVal[1]
			if family == 0x01 {
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

		if at == 0x0001 && al >= 8 {
			family := attrVal[1]
			if family == 0x01 {
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
