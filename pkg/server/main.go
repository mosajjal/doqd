package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"log"

	doq "github.com/mosajjal/doqd"
)

// Server stores a DoQ server
type Server struct {
	Upstream string
	Listener quic.Listener
	Debug    bool
}

type Config struct {
	ListenAddr string
	Cert       tls.Certificate
	Upstream   string
	TLSCompat  bool
	Debug      bool
}

// New constructs a new Server
func New(c Config) (*Server, error) {
	// Select TLS protocols for DoQ
	var tlsProtos []string
	if c.TLSCompat {
		tlsProtos = doq.TlsProtosCompat
	} else {
		tlsProtos = doq.TlsProtos
	}

	// Create QUIC listener
	listener, err := quic.ListenAddr(c.ListenAddr, &tls.Config{
		Certificates: []tls.Certificate{c.Cert},
		NextProtos:   tlsProtos,
	}, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		return nil, errors.New("could not start QUIC listener: " + err.Error())
	}

	return &Server{Listener: *listener, Upstream: c.Upstream}, nil // nil error
}

// Listen starts accepting QUIC connections
func (s *Server) Listen() {
	// Accept QUIC connections
	for {
		session, err := s.Listener.Accept(context.Background())
		if err != nil {
			if s.Debug {
				log.Printf("QUIC accept: %v", err)
			}
			break
		} else {
			// Handle QUIC session in a new goroutine
			go s.handleDoQSession(session, s.Upstream)
		}
	}
}

// handleDoQSession handles a new DoQ session
func (s *Server) handleDoQSession(session *quic.Conn, upstream string) {
	for {
		// Accept client-originated QUIC stream
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			if s.Debug {
				log.Printf("QUIC stream accept: %v", err)
			}
			_ = session.CloseWithError(doq.InternalError, "") // Close the session with an internal error message
			return
		}

		// Handle QUIC stream (DNS query) in a new goroutine
		go func() {
			// Increment query metric
			metricQueries.Inc()

			// The client MUST send the DNS query over the selected stream, and MUST
			// indicate through the STREAM FIN mechanism that no further data will
			// be sent on that stream.
			bytes, err := io.ReadAll(stream) // Ignore error, error handling is done by packet length

			// Check for packet to small
			if len(bytes) < 17 { // MinDnsPacketSize
				switch {
				case err != nil:
					if s.Debug {
						log.Printf("QUIC stream read: %v", err)
					}
				default:
					if s.Debug {
						log.Printf("DNS query length is too small")
					}
				}
				return
			}

			// Unpack the incoming DNS message
			msg := dns.Msg{}
			err = msg.Unpack(bytes)
			if err != nil {
				if s.Debug {
					log.Printf("DNS query unpack error: %v", err)
				}
			}

			// If any message sent on a DoQ connection contains an edns-tcp-keepalive EDNS(0) Option,
			// this is a fatal error and the recipient of the defective message MUST forcibly abort
			// the connection immediately.
			if opt := msg.IsEdns0(); opt != nil {
				for _, option := range opt.Option {
					// Check for EDNS TCP keepalive option
					if option.Option() == dns.EDNS0TCPKEEPALIVE {
						_ = stream.Close() // Ignore error if we're already trying to forcibly close the stream
						return
					}
				}
			}

			// https://datatracker.ietf.org/doc/html/draft-ietf-dprive-dnsoquic-02#section-6.4
			// When sending queries over a QUIC connection, the DNS Message ID MUST be set to zero.
			id := msg.Id
			var reply *dns.Msg
			msg.Id = 0
			defer func() {
				// Restore the original ID to not break compatibility with proxies
				msg.Id = id
				if reply != nil {
					reply.Id = id
				}
			}()

			// Query the upstream for our DNS response
			resp, err := s.sendUDPDNSMsg(msg, upstream)
			if err != nil {
				metricUpstreamErrors.Inc()
				if s.Debug {
					log.Printf("DNS query error: %v", err)
				}
			}

			// Increment valid queries metric
			metricValidQueries.Inc()

			// Pack the response into a byte slice
			bytes, err = resp.Pack()
			if err != nil {
				if s.Debug {
					log.Printf("DNS response pack error: %v", err)
				}
			}

			// Send the byte slice over the open QUIC stream
			n, err := stream.Write(bytes)
			if err != nil {
				if s.Debug {
					log.Printf("QUIC stream write: %v", err)
				}
			}
			if n != len(bytes) {
				if s.Debug {
					log.Printf("QUIC stream write length mismatch")
				}
			}

			// Ignore error since we're already trying to close the stream
			_ = stream.Close()
		}()
	}
}

func (s *Server) sendUDPDNSMsg(msg dns.Msg, upstream string) (dns.Msg, error) {
	// Pack the DNS message
	packed, err := msg.Pack()
	if err != nil {
		return dns.Msg{}, err
	}

	// Connect to the DNS upstream
	if s.Debug {
		log.Printf("dialing udp dns upstream: %s", upstream)
	}
	conn, err := net.Dial("udp", upstream)
	if err != nil {
		return dns.Msg{}, errors.New("upstream connect: " + err.Error())
	}

	// Send query to DNS upstream
	if s.Debug {
		log.Printf("writing query to dns upstream: %s", upstream)
	}
	_, err = conn.Write(packed)
	if err != nil {
		return dns.Msg{}, errors.New("upstream query write: " + err.Error())
	}

	// Read the query response from the upstream
	if s.Debug {
		log.Printf("reading query response from dns upstream: %s", upstream)
	}
	buf := make([]byte, 4096)
	size, err := conn.Read(buf)
	if err != nil {
		return dns.Msg{}, errors.New("upstream query read: " + err.Error())
	}

	// Pack the response message
	var retMsg dns.Msg
	err = retMsg.Unpack(buf[:size])
	if err != nil {
		return dns.Msg{}, err
	}

	return retMsg, nil // nil error
}
