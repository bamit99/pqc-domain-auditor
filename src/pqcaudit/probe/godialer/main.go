// godialer is a minimal TLS probe binary used as a fallback backend for
// pqc-domain-auditor when OpenSSL >= 3.5 is unavailable.
//
// Go's crypto/tls has shipped the X25519MLKEM768 hybrid key exchange since
// Go 1.24 (no third-party fork required). Each invocation performs ONE probe
// and prints a single JSON object on stdout (one line). The Python side
// drives the same probe matrix it uses with openssl s_client.
//
// Probe modes:
//
//	default     normal modern client offer (negotiated group recovered from ServerHello)
//	hybrid      force hybrid ML-KEM groups first -> does the server accept hybrid PQ?
//	pure        force pure ML-KEM (MLKEM1024)    -> does the server accept pure ML-KEM?
//	            (Go 1.24 only implements pure key exchange for MLKEM1024; pure
//	            MLKEM512/MLKEM768 are not wired into crypto/tls. The OpenSSL
//	            backend covers the full pure MLKEM512/768/1024 range.)
//	classical   force X25519/P-256               -> is classical fallback preserved?
//	legacy      unsupported (Go dropped TLS 1.0/1.1 clients; use OpenSSL)
//
// crypto/tls does not expose the negotiated key-exchange group via
// ConnectionState, so the dialer records the raw handshake bytes and parses
// the selected group out of the ServerHello key_share extension.
//
// Usage: godialer -host example.com -port 443 -probe default [-timeout 10]
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	extKeyShare     = 0x0033
	recordHandshake = 0x16
	handshakeHello  = 0x02
	// IANA TLS Supported Groups (authoritative codepoints from the registry).
	// Go 1.24 crypto/tls implements key exchange for: X25519MLKEM768,
	// SecP256r1MLKEM768, SecP384r1MLKEM1024 (hybrids) and MLKEM1024 (pure).
	// Pure MLKEM512/MLKEM768 are NOT wired into Go's TLS stack — offering them
	// would advertise them on the wire but fail at key-exchange time. The
	// previous values (0x11e9/0x11ea/0x11eb) were wrong: they are hybrid groups
	// (SecP256r1MLKEM512 / MLKEM512X25519 / SecP256r1MLKEM768), not pure.
	mlkem1024  CurveID = 0x0202 // 514  — pure ML-KEM-1024 (FIPS 203)
	hybrid768  CurveID = 0x11ec // 4588 — X25519MLKEM768
	hybrid256  CurveID = 0x11eb // 4587 — SecP256r1MLKEM768
	hybrid384  CurveID = 0x11ed // 4589 — SecP384r1MLKEM1024
)

type CurveID = tls.CurveID

type probeResult struct {
	Probe        string `json:"probe"`
	OK           bool   `json:"ok"`
	TLSVersion   string `json:"tls_version,omitempty"`
	Cipher       string `json:"cipher,omitempty"`
	Group        string `json:"group,omitempty"`
	SigAlg       string `json:"sig_alg,omitempty"`
	CertDERB64   string `json:"cert_der_b64,omitempty"`
	ServerHeader string `json:"server_header,omitempty"`
	Error        string `json:"error,omitempty"`
}

func versionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return ""
	}
}

// recordingConn buffers the raw handshake bytes so we can inspect the
// ServerHello and recover the negotiated group after the handshake.
type recordingConn struct {
	net.Conn
	first bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.first.Len() < 4096 {
		c.first.Write(p[:n])
	}
	return n, err
}

// serverHelloGroup returns the TLS 1.3 group selected in the ServerHello
// key_share extension, or 0 if it cannot be determined (TLS 1.2 handshake,
// truncation, or a non-ServerHello first record).
func (c *recordingConn) serverHelloGroup() uint16 {
	data := c.first.Bytes()
	if len(data) < 11 || data[0] != recordHandshake || data[5] != handshakeHello {
		return 0
	}
	p := 9 + 2 + 32 // handshake hdr + legacy_version + random
	if p+1 > len(data) {
		return 0
	}
	sidLen := int(data[p])
	p += 1 + sidLen + 2 + 1 // session_id + cipher_suite + compression
	if p+2 > len(data) {
		return 0
	}
	extLen := int(data[p])<<8 | int(data[p+1])
	p += 2
	end := p + extLen
	if end > len(data) {
		return 0
	}
	for p+4 <= end {
		typ := int(data[p])<<8 | int(data[p+1])
		l := int(data[p+2])<<8 | int(data[p+3])
		p += 4
		if p+l > end {
			break
		}
		if typ == extKeyShare && l >= 2 {
			return uint16(data[p])<<8 | uint16(data[p+1])
		}
		p += l
	}
	return 0
}

func curvesForProbe(probe string) []tls.CurveID {
	switch probe {
	case "hybrid":
		// Offer ONLY hybrid groups so a server with X25519-first ordering
		// cannot fall back to classical (mirrors openssl -groups X25519MLKEM768).
		// X25519MLKEM768 first since that's the deployment-recommended hybrid;
		// the SecP-based hybrids are additional signal for hybrid_supported.
		return []tls.CurveID{tls.CurveID(hybrid768), tls.CurveID(hybrid256), tls.CurveID(hybrid384)}
	case "pure":
		// Go 1.24 only implements pure key exchange for MLKEM1024 (0x0202).
		// Pure MLKEM512/MLKEM768 are not wired into crypto/tls — offering them
		// would advertise them on the wire but fail at key-exchange time, so we
		// do not offer them here. (The OpenSSL backend covers MLKEM512/768.)
		return []tls.CurveID{tls.CurveID(mlkem1024)}
	case "classical":
		return []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	default: // "default"
		return nil
	}
}

// readServerHeader sends a minimal HTTP/1.1 request and captures the Server
// header (used for stack detection / targeted remediation). Best-effort.
func readServerHeader(conn *tls.Conn, host string, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	req := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: pqc-domain-auditor\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	rd := bufio.NewReader(conn)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return ""
		}
		trim := strings.TrimRight(line, "\r\n")
		if trim == "" {
			return ""
		}
		if len(trim) > 7 && strings.EqualFold(trim[:7], "Server:") {
			return strings.TrimSpace(trim[7:])
		}
	}
}

func runProbe(probe, host string, port int, timeout time.Duration) probeResult {
	res := probeResult{Probe: probe}
	if probe == "legacy" {
		res.Error = "Go client does not support TLS 1.0/1.1; use the OpenSSL backend for the legacy probe"
		return res
	}

	addr := net.JoinHostPort(host, fmt.Sprint(port))
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Error = fmt.Sprintf("dial failed: %v", err)
		return res
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		res.Error = fmt.Sprintf("set deadline failed: %v", err)
		return res
	}

	rec := &recordingConn{Conn: raw}
	cfg := &tls.Config{
		ServerName:       host,
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: curvesForProbe(probe),
		NextProtos:       []string{"http/1.1"},
	}
	// Note: we do not set Config.CipherSuites. Go treats it as a whitelist
	// filter only - the TLS 1.3 suite ORDER always follows Go's own
	// [AES-128-GCM, AES-256-GCM, ChaCha20]. All TLS 1.3 suites are quantum-safe
	// AEADs, and the scoring model counts all of them, so the negotiated suite
	// does not change the readiness score.
	conn := tls.Client(rec, cfg)
	if err := conn.Handshake(); err != nil {
		res.Error = fmt.Sprintf("handshake failed: %v", err)
		return res
	}
	defer conn.Close()

	state := conn.ConnectionState()
	res.OK = true
	res.TLSVersion = versionString(state.Version)
	res.Cipher = tls.CipherSuiteName(state.CipherSuite)
	if g := rec.serverHelloGroup(); g != 0 {
		res.Group = tls.CurveID(g).String()
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		res.SigAlg = cert.SignatureAlgorithm.String()
		res.CertDERB64 = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	if probe == "default" && (state.NegotiatedProtocol == "" || state.NegotiatedProtocol == "http/1.1") {
		res.ServerHeader = readServerHeader(conn, host, timeout)
	}
	return res
}

func main() {
	host := flag.String("host", "", "hostname or IP to connect to (SNI host)")
	port := flag.Int("port", 443, "TCP port")
	probe := flag.String("probe", "default", "probe mode: default|hybrid|pure|classical|legacy")
	timeoutSec := flag.Float64("timeout", 10.0, "per-probe timeout in seconds")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "godialer: -host is required")
		os.Exit(2)
	}
	res := runProbe(*probe, *host, *port, time.Duration(*timeoutSec*float64(time.Second)))
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "godialer: encode error: %v\n", err)
		os.Exit(1)
	}
}
