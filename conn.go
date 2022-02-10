//A net.Conn implementation which can change tls.TLSConn from net.TCPConn when a TLS ClientHello received.
//It should be used with net.TCPListener.Accept() as underlying connection for BufferConn and the BufferConn should be used for Conn as underlying connection.
//For implementation example check the test files.
package hybrid_tcp_tls_conn

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

//Conn implements the net.Conn interface.
//Which can change the underlying connection from TCP to TLS if a TLS ClientHello received.
type Conn struct {
	connection net.Conn
	lock       sync.RWMutex
	tlsConfig *tls.Config
	tls        bool
}

//Read from the underlying connection.
//If TLS ClientHello received execute tls.TLSConn.Handshake() and read again for the actual message.
func (connection *Conn) Read(buffer []byte) (int, error) {
	var connectionBuffer *BufferConn
	length, error := connection.connection.Read(buffer)

	if buffer[0] == byte(0x16) && buffer[5] == byte(0x1) && (length-5) == int(int32(buffer[3])<<8+int32(buffer[4])) && (length-9) == int(int32(buffer[6])<<16+int32(buffer[7])<<8+int32(buffer[8])) {
		connectionBuffer = connection.connection.(*BufferConn)
		connectionBuffer.SetBuffer(buffer[:length])
		connection.lock.Lock()
		connectionTls := tls.Server(connection.connection, connection.tlsConfig)
		connectionTls.Handshake()
		connection.connection = connectionTls
		connection.tls = true
		connection.lock.Unlock()
		length, error = connection.connection.Read(buffer)
	}

	return length, error
}

//Write to the underlying connection.
func (connection *Conn) Write(buffer []byte) (int, error) {
	connection.lock.Lock()
	defer connection.lock.Unlock()
	length, error := connection.connection.Write(buffer)
	return length, error
}

//Close the underlying connection.
func (connection *Conn) Close() error {
	error := connection.connection.Close()
	return error
}

//LocalAddr of the underlying connection.
func (connection *Conn) LocalAddr() net.Addr {
	address := connection.connection.LocalAddr()
	return address
}

//RemoteAddr of the underlying connection.
func (connection *Conn) RemoteAddr() net.Addr {
	address := connection.connection.RemoteAddr()
	return address
}

//SetDeadline to the underlying connection.
func (connection *Conn) SetDeadline(time time.Time) error {
	error := connection.connection.SetDeadline(time)
	return error
}

//SetReadDeadline to the underlying connection.
func (connection *Conn) SetReadDeadline(time time.Time) error {
	error := connection.connection.SetReadDeadline(time)
	return error
}

//SetWriteDeadline to the underlying connection.
func (connection *Conn) SetWriteDeadline(time time.Time) error {
	error := connection.connection.SetWriteDeadline(time)
	return error
}

//GetTls returns true if the underlying connection is using TLS and false if not.
func (connection *Conn) GetTls() bool {
	return connection.tls
}

//SetTlsConfig change the TLS server configuration.
//New connection will be not generated if you change it and TLS is already in use.
func (connection *Conn) SetTlsConfig(tlsConfig *tls.Config) {
	connection.tlsConfig = tlsConfig
}

//GetTlsConfig returns the TLS server configuration.
func (connection *Conn) GetTlsConfig() *tls.Config {
	return connection.tlsConfig
}

//New returns a new Conn using connection converted to BufferConn as the underlying connection.
//The configuration config must be non-nil and must include at least one certificate or else set GetCertificate, if TLS will be added to the connection.
func New(connection net.Conn, tlsConfig *tls.Config) *Conn {
	return &Conn{connection: CreateBufferConn(connection), lock: sync.RWMutex{}, tlsConfig: tlsConfig}
}
