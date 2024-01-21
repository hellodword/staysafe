package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/natesales/q/transport"
)

func init() {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")
}

func answer(r *dns.Msg) []dns.RR {
	if r != nil {
		return r.Answer
	} else {
		return nil
	}
}

func process(tag string, ts transport.Transport, m *dns.Msg) {
	result, err := ts.Exchange(m)
	fmt.Println(tag, "\t", answer(result), err)
}

func main() {
	m := new(dns.Msg)
	m.SetQuestion("github.com.", dns.TypeA)

	{
		srcIP := net.ParseIP("1.1.1.1")

		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		if ip := srcIP.To4(); ip != nil {
			e.Family = 1
			e.SourceNetmask = 24
			e.Address = ip.To4()
		} else {
			e.Family = 2
			e.SourceNetmask = 48
			e.Address = srcIP
		}
		opt.Option = append(opt.Option, e)
		m.Extra = append(m.Extra, opt)
	}

	timeout := time.Second * 3

	{
		ts := &transport.Plain{
			Timeout:   timeout,
			Server:    "8.8.8.8:53",
			PreferTCP: false,
		}

		process("UDP", ts, m)
	}

	{
		ts := &transport.Plain{
			Timeout:   timeout,
			Server:    "8.8.8.8:53",
			PreferTCP: true,
		}

		process("TCP", ts, m)
	}

	{
		ts := &transport.TLS{
			Timeout: timeout,
			Server:  "8.8.8.8:853",
		}

		process("DoT", ts, m)
	}

	{
		ts := &transport.HTTP{
			Timeout: timeout,
			Server:  "https://8.8.8.8/dns-query",
			HTTP2:   false,
			HTTP3:   false,
			Method:  http.MethodGet,
		}

		process("HTTP/1", ts, m)
	}

	{
		ts := &transport.HTTP{
			Timeout: timeout,
			Server:  "https://8.8.8.8/dns-query",
			HTTP2:   true,
			HTTP3:   false,
			Method:  http.MethodGet,
		}

		process("HTTP/2", ts, m)
	}

	{
		ts := &transport.HTTP{
			Timeout: timeout,
			Server:  "https://8.8.8.8/dns-query",
			HTTP2:   false,
			HTTP3:   true,
			Method:  http.MethodGet,
		}

		process("HTTP/3", ts, m)
	}

	{
		tlsConfig := &tls.Config{
			NextProtos: []string{"doq"},
		}
		ts := &transport.QUIC{
			Server:    "94.140.14.14:853",
			TLSConfig: tlsConfig,
		}

		process("QUIC", ts, m)
	}

	{
		ts := &transport.DNSCrypt{
			Timeout: timeout,
			// adguard
			ServerStamp: "sdns://AQMAAAAAAAAAEzE0OS4xMTIuMTEyLjExOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA",
			TCP:         false,
		}

		process("SDNS/U", ts, m)
	}

	{
		ts := &transport.DNSCrypt{
			Timeout: timeout,
			// adguard
			ServerStamp: "sdns://AQMAAAAAAAAAEzE0OS4xMTIuMTEyLjExOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA",
			TCP:         true,
		}

		process("SDNS/T", ts, m)
	}
}
