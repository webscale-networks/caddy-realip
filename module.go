package realip

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

type module struct {
	next   httpserver.Handler
	From   []*net.IPNet
	Header string

	// MaxHops configures the maxiumum number of hops or IPs to be found in a forward header.
	// It's purpose is to prevent abuse and/or DOS attacks from long forward-chains, since each one
	// must be parsed and checked against a list of subnets.
	// The default is 5, -1 to disable. If set to 0, any request with a forward header will be rejected
	MaxHops int
	Strict  bool
}

func (m *module) validSource(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, from := range m.From {
		if from.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *module) ServeHTTP(w http.ResponseWriter, req *http.Request) (int, error) {

	addr, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		if m.Strict {
			return 403, fmt.Errorf("Error reading remote addr: %s", req.RemoteAddr)
		}
		return m.next.ServeHTTP(w, req) // Change nothing and let next deal with it.
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return m.next.ServeHTTP(w, req) // Change nothing and let next deal with it.
	}

	if !m.validSource(ip) {
		if m.Strict {
			return 403, fmt.Errorf("Unrecognized proxy ip address: %s", addr)
		}
		return m.next.ServeHTTP(w, req)
	}

	hVal := req.Header.Get(m.Header)
	if hVal == "" {
		// Discard any XFF header values for upstream processing.
		req.Header.Del("X-Forwarded-For")
		return m.next.ServeHTTP(w, req)
	}

	//restore original host:port format
	parts := strings.Split(hVal, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	if m.MaxHops != -1 && len(parts) > m.MaxHops {
		return 403, fmt.Errorf("Too many forward addresses")
	}

	// Convert entire parts array into ip address array
	ips := make([]net.IP, len(parts))
	for i := 0; i < len(parts); i++ {
		ip := net.ParseIP(parts[i])
		if ip == nil {
			if m.Strict {
				return 403, fmt.Errorf("Unparsable proxy ip address: %s", parts[i])
			}
			return m.next.ServeHTTP(w, req)
		}
		ips[i] = ip
	}

	for len(ips) > 1 && m.validSource(ips[len(ips)-1]) {
		ips = ips[:len(ips)-1]
		parts = parts[:len(parts)-1]
	}

	req.RemoteAddr = net.JoinHostPort(parts[len(parts)-1], port)
	parts = parts[:len(parts)-1]
	headerval := strings.Join(parts, ",")
	if headerval != "" {
		req.Header.Set("X-Forwarded-For", headerval)
	} else {
		// Discard any XFF header values for upstream processing.
		req.Header.Del("X-Forwarded-For")
	}
	// Discard the incoming header as upstream processing relies on XFF.
	req.Header.Del(m.Header)
	return m.next.ServeHTTP(w, req)
}
