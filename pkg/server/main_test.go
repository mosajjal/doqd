package server

import (
	"crypto/tls"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/mosajjal/doqd/pkg/client"
)

func TestServer(t *testing.T) {
	// generate a self-signed certificate for testing
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgIUUXESkpe8GXn3sZJA3quoaCwEzEwwDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwObXlyZXNvbHZlci54eXowHhcNMjUwNzIyMjMwNjA1WhcN
MjgwNTExMjMwNjA1WjAZMRcwFQYDVQQDDA5teXJlc29sdmVyLnh5ejCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALUCcAlC7tbmaQI5R+Isf2/0zCYqGSLi
YsbuvDgVDWPUSPctUQ1+1FNtZ7QIFuJ4TWll/MfKSEEfNW9uHRZb+bTtmslwZurX
NQLm15xuzHI9ZuNePS9t85UchNZo2GRsX7OHrZrHX96LVDPteS6ue+cpM/FrgDnC
Cu6HipP/WZs7j+jb9Anu5A1O71mKLp7X/sVwJkHJmhx3lGI/xuYTwHAzab1lIciL
dQ9w97HkWvgkL1g+LgrTw541Hyabj/KViV/FfGf+jlKQ5rL1h2LcHQsoOXvIpJv9
UuEOyv2el2XB5A1tX8Ddtj9vnToS+rcNympnokIy/C0G6xt/xJFAp8kCAwEAAaOB
gDB+MB0GA1UdDgQWBBQWzGnj44g9TvSVWFzbQ1FEOCXdyTAfBgNVHSMEGDAWgBQW
zGnj44g9TvSVWFzbQ1FEOCXdyTAPBgNVHRMBAf8EBTADAQH/MCsGA1UdEQQkMCKC
Dm15cmVzb2x2ZXIueHl6ghAqLm15cmVzb2x2ZXIueHl6MA0GCSqGSIb3DQEBCwUA
A4IBAQBfhV3RPQMFDNfbdZyEP5yaOX/9Ym4zWVGWM/T30yZy/kbyzR/vQWf52DpU
iCYL8Af1fyz1Ej2lv1SEEzDKlBnEe5vVGRLLTTdh8Tp1YiJQbMYfTRfYsDzyWDM+
gnNFGBjJf9HLvkitpIzNY+18A99E2clO9CoXe2bHu6OIq6uINaSgLfCvPRmUNkPp
LEyQMNcMuParFJX5g4mwqBtgrt9YJBDSHimMEgW/u6G5+hWBfMfwQ1yFg0XJffur
hjK7Z3s5pPFkykRuO2G0p92AShPuC6EfRteSxG/ROC93XvocW4OGV1Yl5hCYvbQo
Js/yV+Y6lVmJpJFjZTsRviKTLvnk
-----END CERTIFICATE-----`)
	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1AnAJQu7W5mkC
OUfiLH9v9MwmKhki4mLG7rw4FQ1j1Ej3LVENftRTbWe0CBbieE1pZfzHykhBHzVv
bh0WW/m07ZrJcGbq1zUC5tecbsxyPWbjXj0vbfOVHITWaNhkbF+zh62ax1/ei1Qz
7XkurnvnKTPxa4A5wgruh4qT/1mbO4/o2/QJ7uQNTu9Zii6e1/7FcCZByZocd5Ri
P8bmE8BwM2m9ZSHIi3UPcPex5Fr4JC9YPi4K08OeNR8mm4/ylYlfxXxn/o5SkOay
9Ydi3B0LKDl7yKSb/VLhDsr9npdlweQNbV/A3bY/b506Evq3DcpqZ6JCMvwtBusb
f8SRQKfJAgMBAAECggEACx3oNZlnw8kI3/sWoBxtgzm8pAdn3c2blW4qHyOj2+K4
zH17AeItNiZ8/QCWLziGQJfj631P7Lf29y4DGVFyx5rkK8T8fSXUeqYkzdW8NrPw
srwh89zD3f+PZP+xcpF5WzRVBDGEgM170WifTa+nqm3MY+JfUKzLMRUf/LDtFux5
u9eHAeFAocuMBmAzzn11RIrzkwOUtirhCsEUIEeNJb7vklsbLuem3QbyX/8kmZ+v
PF7IBJCLhXxJkDCc2lxYQZ9ATkzwFPnhg+myl6CH0oRpS7enBvxblMfoVMHAVPw3
MhkgcCBiwUY6btC7pUADe2bWRCC0q+kJ4iSH5KLnkQKBgQD+w4sYKgZJy1DTZSTK
4wr3LO1nkBRnp5KnhGFj6aJw2HCjREJ77+zF+agS9htdxu6v0n76/VQZqDO1bKcq
3qtl1/4xdiCHT//H5D2nBwY9ax7kiElZfixg4tXyqnimlotgI4ChIJw8wiLUZ+pt
R7nTIE3qxC0I6OL8XnM+WbOgDQKBgQC140elZ67yN4zogVMfwxktYCUdVjzQpult
foVZzfg/i8xb66Pq2qpmyhwfog6IPfmX8TvmMuy8mDQ6cHuMIaPh5Q0RuydWM1oz
PKxlVLRDSYWvxG9IJnEPbqPhgUE4cU0E4TDUK8+R7zaKzkSird70Vlr+eZKm1yTm
VNd6P8S7rQKBgQC9y3/8aJJ2t3lng5p9a9fnfRkAZl5NOpIPKphDjvLtjtGbUGcX
Xg7PDscgGSkaG/IGGpNu+PuGgcDEEEYZsfmOzfMZdh+VrwunJ2qm3JzRdNR2/PFo
Mo9tPpCVUFrCALWk0c4qO9kpipfYFfKXpy/REef6VlwWnyk7SkIg2ULwoQKBgGUB
hAX8oBBufNeZCbo3s8GZBMNX4onURwjBG/iVAuj3D1N0diCzsbFHR3rhmcRa9kJE
eokJeqH4u/hAArv86m9FrY5NKjkaZ1rQtMPI2BoNuCm1oj6k6mAxhtxx1PAtKyIs
k9sfQTO/bcCDb2YPvCJf2kQ66w+vphQqxUZkJzI5AoGBAKoDKkMyC02yusaYAoTR
qabYGua/cFTsZxZVaDuqRXeN7MomzoXV6Es1GxbNKLGJFMowPPUEYHrcBFlt5H4K
7QQOBxnylDdXeM0MTE2Nxc2d3aF3gzMX56LXwOBbKYqsNNw9AYHoxMFXtR8hUT46
cnCtEMZ1J/rwNybogJRCZ5DZ
-----END PRIVATE KEY-----`)
	// Load the certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	assert.Nil(t, err)

	// Create the QUIC listener
	serverCfg := Config{
		ListenAddr: "localhost:8853",
		Cert:       cert,
		Upstream:   "1.1.1.1:53",
		TLSCompat:  false,
	}
	doqServer, err := New(serverCfg)
	assert.Nil(t, err)

	// Start the server
	go doqServer.Listen()

	// Create the DoQ client
	clientCfg := client.Config{
		Server:        "localhost:8853",
		TLSSkipVerify: true,
		Compat:        false,
		Debug:         false,
	}
	doqClient, err := client.New(clientCfg)
	assert.Nil(t, err)

	// Create a test DNS query
	req := dns.Msg{
		Question: []dns.Question{{
			Name:   dns.Fqdn("example.com"),
			Qtype:  dns.StringToType["A"],
			Qclass: dns.ClassINET,
		}},
	}
	req.RecursionDesired = true

	// Send the query
	_, err = doqClient.SendQuery(req)
	assert.Nil(t, err)
}
