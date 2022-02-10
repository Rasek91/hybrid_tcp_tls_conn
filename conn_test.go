package hybrid_tcp_tls_conn

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

func tcpClient(message []byte) {
	client, _ := net.Dial("tcp", "127.0.0.1:8080")
	client.Write(message)
}

func tlsClient(message []byte) {
	clientTcp, _ := net.Dial("tcp", "127.0.0.1:8080")
	client := tls.Client(clientTcp, &tls.Config{InsecureSkipVerify: true})
	client.Write(message)
}

func TestTcp(test *testing.T) {
	message := []byte{0x01, 0x01}
	listener, error := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})

	if error != nil {
		test.Error("ListenTCP error ", error)
	}

	defer listener.Close()
	go tcpClient(message)

	for {
		connection, error := listener.Accept()

		if error != nil {
			test.Error("Accept error ", error)
		}

		connectionHybrid := New(connection, nil)
		defer connectionHybrid.Close()
		buffer := make([]byte, 1024)
		length, error := connectionHybrid.Read(buffer)

		if error != nil {
			test.Error("Read error ", error)
		}

		test.Log("message", buffer[:length])

		if connectionHybrid.GetTls() {
			test.Error("GetTls error")
		}

		if length != len(message) || !reflect.DeepEqual(message, buffer[:length]) {
			test.Error("messages not match ", message, buffer[:length])
		}

		break
	}
}

func TestTls(test *testing.T) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, error := rsa.GenerateKey(rand.Reader, 4096)
	if error != nil {
		test.Error("CA Private Key error ", error)
	}

	caBytes, error := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if error != nil {
		test.Error("CA Bytes error ", error)
	}

	caPem := new(bytes.Buffer)
	pem.Encode(caPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivateKeyPem := new(bytes.Buffer)
	pem.Encode(caPrivateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, error := rsa.GenerateKey(rand.Reader, 4096)
	if error != nil {
		test.Error("Cert Private Key error ", error)
	}

	certBytes, error := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivateKey.PublicKey, caPrivateKey)
	if error != nil {
		test.Error("Cert Bytes error ", error)
	}

	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivateKeyPem := new(bytes.Buffer)
	pem.Encode(certPrivateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})

	serverCert, error := tls.X509KeyPair(certPem.Bytes(), certPrivateKeyPem.Bytes())
	if error != nil {
		test.Error("Server Cert error ", error)
	}

	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	test.Log("TLS Cert generated")
	message := []byte{0x01, 0x01}
	listener, error := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})

	if error != nil {
		test.Error("ListenTCP error ", error)
	}

	defer listener.Close()
	go tlsClient(message)

	for {
		connection, error := listener.Accept()

		if error != nil {
			test.Error("Accept error ", error)
		}

		connectionHybrid := New(connection, serverTlsConfig)
		defer connectionHybrid.Close()
		buffer := make([]byte, 1024)
		length, error := connectionHybrid.Read(buffer)

		if error != nil {
			test.Error("Read error ", error)
		}

		test.Log("message", buffer[:length])

		if !connectionHybrid.GetTls() {
			test.Error("GetTls error")
		}

		if length != len(message) || !reflect.DeepEqual(message, buffer[:length]) {
			test.Error("messages not match ", message, buffer[:length])
		}

		break
	}
}
