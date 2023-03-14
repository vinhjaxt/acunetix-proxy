package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// from goproxy

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIIF9DCCA9ygAwIBAgIJAODqYUwoVjJkMA0GCSqGSIb3DQEBCwUAMIGOMQswCQYD
VQQGEwJJTDEPMA0GA1UECAwGQ2VudGVyMQwwCgYDVQQHDANMb2QxEDAOBgNVBAoM
B0dvUHJveHkxEDAOBgNVBAsMB0dvUHJveHkxGjAYBgNVBAMMEWdvcHJveHkuZ2l0
aHViLmlvMSAwHgYJKoZIhvcNAQkBFhFlbGF6YXJsQGdtYWlsLmNvbTAeFw0xNzA0
MDUyMDAwMTBaFw0zNzAzMzEyMDAwMTBaMIGOMQswCQYDVQQGEwJJTDEPMA0GA1UE
CAwGQ2VudGVyMQwwCgYDVQQHDANMb2QxEDAOBgNVBAoMB0dvUHJveHkxEDAOBgNV
BAsMB0dvUHJveHkxGjAYBgNVBAMMEWdvcHJveHkuZ2l0aHViLmlvMSAwHgYJKoZI
hvcNAQkBFhFlbGF6YXJsQGdtYWlsLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBAJ4Qy+H6hhoY1s0QRcvIhxrjSHaO/RbaFj3rwqcnpOgFq07gRdI9
3c0TFKQJHpgv6feLRhEvX/YllFYu4J35lM9ZcYY4qlKFuStcX8Jm8fqpgtmAMBzP
sqtqDi8M9RQGKENzU9IFOnCV7SAeh45scMuI3wz8wrjBcH7zquHkvqUSYZz035t9
V6WTrHyTEvT4w+lFOVN2bA/6DAIxrjBiF6DhoJqnha0SZtDfv77XpwGG3EhA/qoh
hiYrDruYK7zJdESQL44LwzMPupVigqalfv+YHfQjbhT951IVurW2NJgRyBE62dLr
lHYdtT9tCTCrd+KJNMJ+jp9hAjdIu1Br/kifU4F4+4ZLMR9Ueji0GkkPKsYdyMnq
j0p0PogyvP1l4qmboPImMYtaoFuYmMYlebgC9LN10bL91K4+jLt0I1YntEzrqgJo
WsJztYDw543NzSy5W+/cq4XRYgtq1b0RWwuUiswezmMoeyHZ8BQJe2xMjAOllASD
fqa8OK3WABHJpy4zUrnUBiMuPITzD/FuDx4C5IwwlC68gHAZblNqpBZCX0nFCtKj
YOcI2So5HbQ2OC8QF+zGVuduHUSok4hSy2BBfZ1pfvziqBeetWJwFvapGB44nIHh
WKNKvqOxLNIy7e+TGRiWOomrAWM18VSR9LZbBxpJK7PLSzWqYJYTRCZHAgMBAAGj
UzBRMB0GA1UdDgQWBBR4uDD9Y6x7iUoHO+32ioOcw1ICZTAfBgNVHSMEGDAWgBR4
uDD9Y6x7iUoHO+32ioOcw1ICZTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB
CwUAA4ICAQAaCEupzGGqcdh+L7BzhX7zyd7yzAKUoLxFrxaZY34Xyj3lcx1XoK6F
AqsH2JM25GixgadzhNt92JP7vzoWeHZtLfstrPS638Y1zZi6toy4E49viYjFk5J0
C6ZcFC04VYWWx6z0HwJuAS08tZ37JuFXpJGfXJOjZCQyxse0Lg0tuKLMeXDCk2Y3
Ba0noeuNyHRoWXXPyiUoeApkVCU5gIsyiJSWOjhJ5hpJG06rQNfNYexgKrrraEin
o0jmEMtJMx5TtD83hSnLCnFGBBq5lkE7jgXME1KsbIE3lJZzRX1mQwUK8CJDYxye
i6M/dzSvy0SsPvz8fTAlprXRtWWtJQmxgWENp3Dv+0Pmux/l+ilk7KA4sMXGhsfr
bvTOeWl1/uoFTPYiWR/ww7QEPLq23yDFY04Q7Un0qjIk8ExvaY8lCkXMgc8i7sGY
VfvOYb0zm67EfAQl3TW8Ky5fl5CcxpVCD360Bzi6hwjYixa3qEeBggOixFQBFWft
8wrkKTHpOQXjn4sDPtet8imm9UYEtzWrFX6T9MFYkBR0/yye0FIh9+YPiTA6WB86
NCNwK5Yl6HuvF97CIH5CdgO+5C7KifUtqTOL8pQKbNwy0S3sNYvB+njGvRpR7pKV
BUnFpB/Atptqr4CUlTXrc5IPLAqAfmwk5IKcwy3EXUbruf9Dwz69YA==
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

var GoproxyCa tls.Certificate

func init() {
	rand.Seed(time.Now().UnixNano())
	var err error
	GoproxyCa, err = tls.X509KeyPair(CA_CERT, CA_KEY)
	if err != nil {
		log.Panicln("Error parsing builtin CA ", err)
	}

	GoproxyCa.Leaf, err = x509.ParseCertificate(GoproxyCa.Certificate[0])
	if err != nil {
		log.Panicln("Error parsing builtin CA Leaf", err)
	}
}

var goproxySignerVersion = ":goroxy1"
var tlsCache = map[string]*tls.Config{}
var tlsCacheLock sync.RWMutex

func getTLSConfig(hostname string) (tlsConfig *tls.Config, err error) {
	var ok bool

	tlsCacheLock.RLock()
	tlsConfig, ok = tlsCache[hostname]
	tlsCacheLock.RUnlock()
	if ok {
		return
	}

	if net.ParseIP(hostname) != nil {
		// it's ip
		// gen tlsconfig
		tlsConfig, err = genTlsConfig([]string{hostname})
		if err != nil {
			return
		}
		tlsCacheLock.Lock()
		tlsCache[hostname] = tlsConfig
		tlsCacheLock.Unlock()
		return
	}

	mainDomain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil || mainDomain == hostname {
		tlsConfig, err = genTlsConfig([]string{hostname, "*." + hostname})
		if err != nil {
			return
		}
		tlsCacheLock.Lock()
		tlsCache[hostname] = tlsConfig
		tlsCacheLock.Unlock()
		return
	}

	var hostnames []string
	keys := []string{mainDomain, hostname}
	start := 0
	for {
		idx := strings.IndexByte(hostname[start:], byte('.'))
		if idx == -1 {
			break
		}
		start += idx + 1
		subdomain := hostname[start:]
		if len(hostnames) == 0 {
			// first top domain
			tlsCacheLock.RLock()
			tlsConfig, ok = tlsCache[subdomain]
			tlsCacheLock.RUnlock()
			if ok {
				return
			}
		}
		if subdomain == mainDomain {
			break
		}
		keys = append(keys, subdomain)
		hostnames = append(hostnames, subdomain)
		hostnames = append(hostnames, "*."+subdomain)
	}
	hostnames = append(hostnames, mainDomain)
	hostnames = append(hostnames, "*."+mainDomain)
	hostnames = append(hostnames, hostname)
	hostnames = append(hostnames, "*."+hostname)

	tlsConfig, err = genTlsConfig(hostnames)
	if err != nil {
		return
	}

	tlsCacheLock.Lock()
	for _, key := range keys {
		_, ok = tlsCache[key]
		if !ok {
			tlsCache[key] = tlsConfig
		}
	}
	tlsCacheLock.Unlock()
	return
}

func genTlsConfig(hostnames []string) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	cert, err := signHost(GoproxyCa, hostnames)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
	return tlsConfig, nil
}

func signHost(ca tls.Certificate, hosts []string) (cert *tls.Certificate, err error) {
	// Use the provided ca and not the global GoproxyCa for certificate generation.
	x509ca, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return
	}

	start := time.Unix(0, 0)
	end, _ := time.Parse("2006-01-02", "2049-12-31")

	serial := big.NewInt(rand.Int63())
	template := x509.Certificate{
		// TODO(elazar): instead of this ugly hack, just encode the certificate and hash the binary form.
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"GoProxy untrusted MITM proxy Inc"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	hash := hashSorted(append(hosts, goproxySignerVersion, ":"+runtime.Version()))
	var csprng CounterEncryptorRand
	if csprng, err = NewCounterEncryptorRandFromKey(ca.PrivateKey, hash); err != nil {
		return
	}

	var certpriv crypto.Signer
	switch ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if certpriv, err = rsa.GenerateKey(&csprng, 2048); err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		if certpriv, err = ecdsa.GenerateKey(elliptic.P256(), &csprng); err != nil {
			return
		}
	default:
		err = fmt.Errorf("unsupported key type %T", ca.PrivateKey)
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(&csprng, &template, x509ca, certpriv.Public(), ca.PrivateKey); err != nil {
		return
	}
	return &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate[0]},
		PrivateKey:  certpriv,
	}, nil
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}
