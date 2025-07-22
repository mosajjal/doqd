package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"

	"log"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	doq "github.com/mosajjal/doqd"
)

// Client stores a DoQ client
type Client struct {
	Session *quic.Conn
	Debug   bool
}

type Config struct {
	Server        string
	TLSSkipVerify bool
	Compat        bool
	Debug         bool
}

// New constructs a new client
func New(c Config) (Client, error) {
	// Select TLS protocols for DoQ
	var tlsProtos []string
	if c.Compat {
		tlsProtos = doq.TlsProtosCompat
	} else {
		tlsProtos = doq.TlsProtos
	}

	// Connect to DoQ server
	if c.Debug {
		log.Println("dialing quic server")
	}
	session, err := quic.DialAddr(context.Background(), c.Server, &tls.Config{
		InsecureSkipVerify: c.TLSSkipVerify,
		NextProtos:         tlsProtos,
	}, nil)
	if err != nil {
		log.Fatalf("failed to connect to the server: %v\n", err)
	}

	return Client{Session: session, Debug: c.Debug}, nil // nil error
}

// Close closes a Client QUIC connection
func (c Client) Close() error {
	if c.Debug {
		log.Println("closing quic session")
	}
	return c.Session.CloseWithError(0, "")
}

// SendQuery sends query over a new QUIC stream
func (c Client) SendQuery(message dns.Msg) (dns.Msg, error) {
	// Open a new QUIC stream
	if c.Debug {
		log.Println("opening new quic stream")
	}
	stream, err := c.Session.OpenStream()
	if err != nil {
		return dns.Msg{}, errors.New("quic stream open: " + err.Error())
	}

	// Pack the DNS message for transmission
	if c.Debug {
		log.Println("packing dns message")
	}
	packed, err := message.Pack()
	if err != nil {
		_ = stream.Close()
		return dns.Msg{}, errors.New("dns message pack: " + err.Error())
	}

	// Send the DNS query over QUIC
	if c.Debug {
		log.Println("writing packed format to the stream")
	}
	_, err = stream.Write(packed)
	_ = stream.Close()
	if err != nil {
		return dns.Msg{}, errors.New("quic stream write: " + err.Error())
	}

	// Read the response
	if c.Debug {
		log.Println("reading server response")
	}
	response, err := io.ReadAll(stream)
	if err != nil {
		return dns.Msg{}, errors.New("quic stream read: " + err.Error())
	}

	// Unpack the DNS message
	if c.Debug {
		log.Println("unpacking response dns message")
	}
	var msg dns.Msg
	err = msg.Unpack(response)
	if err != nil {
		return dns.Msg{}, errors.New("dns message unpack: " + err.Error())
	}

	return msg, nil // nil error
}
