package dnsresolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type testDNS struct {
	resolver *net.Resolver
	address  string
	queries  atomic.Int32
	tcp      atomic.Int32
}

// Actual UDP/TCP servers reproduce a socket that opens but never answers.
func startTestDNS(t *testing.T, ip, mode string) *testDNS {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	server := &testDNS{address: udp.LocalAddr().String()}
	server.resolver = serverResolver(server.address)
	t.Cleanup(func() { udp.Close(); tcp.Close() })
	answer := func(packet []byte, isTCP bool) []byte {
		server.queries.Add(1)
		if mode == "silent" {
			return nil
		}
		var query dnsmessage.Message
		if query.Unpack(packet) != nil {
			return nil
		}
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: query.Questions}
		if mode == "nxdomain" {
			response.Header.RCode = dnsmessage.RCodeNameError
		}
		if mode == "truncated" && !isTCP {
			response.Header.Truncated = true
		}
		for _, question := range query.Questions {
			if mode == "nxdomain" || response.Header.Truncated {
				continue
			}
			parsed := net.ParseIP(ip)
			resource := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}}
			if question.Type == dnsmessage.TypeA && parsed.To4() != nil {
				body := &dnsmessage.AResource{}
				copy(body.A[:], parsed.To4())
				resource.Body = body
			} else if question.Type == dnsmessage.TypeAAAA && parsed != nil && parsed.To4() == nil {
				body := &dnsmessage.AAAAResource{}
				copy(body.AAAA[:], parsed.To16())
				resource.Body = body
			} else {
				continue
			}
			response.Answers = append(response.Answers, resource)
		}
		packed, _ := response.Pack()
		return packed
	}
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			if response := answer(buffer[:n], false); response != nil {
				udp.WriteTo(response, peer)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				packet := make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(conn, packet); err != nil {
					return
				}
				server.tcp.Add(1)
				if response := answer(packet, true); response != nil {
					binary.BigEndian.PutUint16(length[:], uint16(len(response)))
					conn.Write(append(length[:], response...))
				}
			}()
		}
	}()
	return server
}

func testAddress(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return net.JoinHostPort("panel.invalid", port), func() { listener.Close() }
}

func TestDNSFallbackOnQueryTimeoutAndConnectionFailure(t *testing.T) {
	for _, mode := range []string{"silent", "nxdomain", "unreachable-address"} {
		t.Run(mode, func(t *testing.T) {
			address, _ := testAddress(t)
			primary := startTestDNS(t, "127.0.0.2", mode)
			fallback := startTestDNS(t, "127.0.0.1", "healthy")
			dial := newDialContext(time.Second, "4", []resolverSource{{"primary", primary.resolver}, {"backup", fallback.resolver}}, 150*time.Millisecond)
			conn, err := dial(context.Background(), "tcp4", address)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if fallback.queries.Load() == 0 {
				t.Fatal("fallback DNS was never queried")
			}
		})
	}
}

func TestHealthyPrimaryDoesNotQueryFallback(t *testing.T) {
	address, _ := testAddress(t)
	primary := startTestDNS(t, "127.0.0.1", "healthy")
	backup := startTestDNS(t, "", "silent")
	dial := newDialContext(time.Second, "4", []resolverSource{{"system", primary.resolver}, {"DNS64", backup.resolver}}, 150*time.Millisecond)
	conn, err := dial(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if backup.queries.Load() != 0 {
		t.Fatal("healthy system path contacted DNS64")
	}
}

func TestCancellationDoesNotStartFallback(t *testing.T) {
	primary := startTestDNS(t, "", "silent")
	backup := startTestDNS(t, "127.0.0.1", "healthy")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	dial := newDialContext(time.Second, "4", []resolverSource{{"system", primary.resolver}, {"DNS64", backup.resolver}}, 150*time.Millisecond)
	if _, err := dial(ctx, "tcp", "panel.invalid:443"); err == nil {
		t.Fatal("cancelled dial succeeded")
	}
	if backup.queries.Load() != 0 {
		t.Fatal("cancelled request contacted backup")
	}
}

func TestTruncatedDNSResponseRetriesTCP(t *testing.T) {
	address, _ := testAddress(t)
	primary := startTestDNS(t, "127.0.0.1", "truncated")
	dial := newDialContext(time.Second, "4", []resolverSource{{"DNS", primary.resolver}}, 500*time.Millisecond)
	conn, err := dial(context.Background(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if primary.tcp.Load() == 0 {
		t.Fatal("truncated response did not retry TCP")
	}
}

func TestIPv6FallbackAfterSystemOnlyReturnsIPv4(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	primary := startTestDNS(t, "127.0.0.2", "healthy")
	backup := startTestDNS(t, "::1", "healthy")
	dial := newDialContext(time.Second, "6", []resolverSource{{"system", primary.resolver}, {"DNS64", backup.resolver}}, 150*time.Millisecond)
	conn, err := dial(context.Background(), "tcp6", net.JoinHostPort("panel.invalid", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if backup.queries.Load() == 0 {
		t.Fatal("IPv6-only connection did not try DNS64")
	}
}

func TestPublicClientsAndLegacyDNS64UseSystemFirst(t *testing.T) {
	oldSystem, oldCustom, oldFallback := net.DefaultResolver, CustomDNSServer, FallbackDNSServer
	t.Cleanup(func() { net.DefaultResolver, CustomDNSServer, FallbackDNSServer = oldSystem, oldCustom, oldFallback })
	primary := startTestDNS(t, "127.0.0.1", "healthy")
	backup := startTestDNS(t, "", "silent")
	net.DefaultResolver = primary.resolver
	SetCustomDNSServer(DefaultDNS64)
	if sources := resolverSources(); sources[0].name != "system DNS" || len(sources) != 2 {
		t.Fatal("legacy DNS64 is not system-first")
	}
	SetCustomDNSServer("")
	SetFallbackDNSServer(backup.address)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	address := net.JoinHostPort("panel.invalid", port)
	client := GetHTTPClient(time.Second)
	// This fixture exercises direct DNS paths, independent of the host's proxy env.
	client.Transport.(*http.Transport).Proxy = nil
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	for _, dial := range []func(context.Context, string, string) (net.Conn, error){GetNetDialer(time.Second).DialContext, GetDialContextWithPreference(time.Second, "4")} {
		conn, err := dial(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	if backup.queries.Load() != 0 {
		t.Fatal("HTTP/network/WebSocket dialer contacted backup on healthy path")
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsServer.Close()
	_, tlsPort, _ := net.SplitHostPort(strings.TrimPrefix(tlsServer.URL, "https://"))
	if _, err := client.Get("https://" + net.JoinHostPort("panel.invalid", tlsPort)); err == nil {
		t.Fatal("untrusted TLS certificate was accepted")
	}
}
