//A net.Conn implementation which can change tls.TLSConn from net.TCPConn when a TLS ClientHello received.
//It should be used with net.TCPListener.Accept() as underlying connection for Buffer_Conn and the Buffer_coon should be used for Conn as underlying connection.
//For iplementation example check the test files.
package hybrid_tcp_tls_conn

import (
	"crypto/tls"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

//Conn implements the net.Conn interface.
//Which can change the underlying connection from TCP to TLS if a TLS ClientHello received.
type Conn struct {
	connection net.Conn
	tls_config *tls.Config
	tls        bool
}

//Read from the underlying connection.
//If TLS ClientHello received execute tls.TLSConn.Handshake() and read again for the actual message.
func (connection *Conn) Read(buffer []byte) (int, error) {
	var connection_buffer *Buffer_Conn
	length, error := connection.connection.Read(buffer)

	if buffer[0] == byte(0x16) && buffer[5] == byte(0x1) && (length-5) == int(int32(buffer[3])<<8+int32(buffer[4])) && (length-9) == int(int32(buffer[6])<<16+int32(buffer[7])<<8+int32(buffer[8])) {
		log.Trace("Client Hello received")
		connection_buffer = connection.connection.(*Buffer_Conn)
		connection_buffer.Set_Buffer(buffer[:length])
		connection_tls := tls.Server(connection.connection, connection.tls_config)
		connection_tls.Handshake()
		connection.connection = connection_tls
		log.Trace("TLS Handshake was successful")
		connection.tls = true
		length, error = connection.connection.Read(buffer)
	}

	log.Trace("get message ", buffer[:length])
	return length, error
}

//Write to the underlying connection.
func (connection *Conn) Write(buffer []byte) (int, error) {
	length, error := connection.connection.Write(buffer)
	log.Trace("sent message ", buffer[:length])
	return length, error
}

//Close the underlying connection.
func (connection *Conn) Close() error {
	error := connection.connection.Close()
	log.Trace("connection close")
	return error
}

//LocalAddr of the underlying connection.
func (connection *Conn) LocalAddr() net.Addr {
	address := connection.connection.LocalAddr()
	log.Trace("LocalAddr")
	return address
}

//RemoteAddr of the underlying connection.
func (connection *Conn) RemoteAddr() net.Addr {
	address := connection.connection.RemoteAddr()
	log.Trace("RemoteAddr")
	return address
}

//SetDeadline to the underlying connection.
func (connection *Conn) SetDeadline(time time.Time) error {
	error := connection.connection.SetDeadline(time)
	log.Trace("SetDeadline")
	return error
}

//SetReadDeadline to the underlying connection.
func (connection *Conn) SetReadDeadline(time time.Time) error {
	error := connection.connection.SetReadDeadline(time)
	log.Trace("SetReadDeadline")
	return error
}

//SetWriteDeadline to the underlying connection.
func (connection *Conn) SetWriteDeadline(time time.Time) error {
	error := connection.connection.SetWriteDeadline(time)
	log.Trace("SetWriteDeadline")
	return error
}

//Get_TLS returns true if the underlying connection is using TLS and false if not.
func (connection *Conn) Get_TLS() bool {
	return connection.tls
}

//Set_TLS_Config change the TLS server configuration.
//New connection will be not generated if you change it and TLS is already in use.
func (connection *Conn) Set_TLS_Config(tls_config *tls.Config) {
	connection.tls_config = tls_config
}

//Get_TLS_Config returns the TLS server configuration.
func (connection *Conn) Get_TLS_Config() *tls.Config {
	return connection.tls_config
}

//Create_Conn returns a new Conn using connection converted to Buffer_Conn as the underlying connection.
//The configuration config must be non-nil and must include at least one certificate or else set GetCertificate, if TLS will be added to the connection.
func Create_Conn(connection net.Conn, tls_config *tls.Config) *Conn {
	return &Conn{connection: Create_Buffer_Conn(connection), tls_config: tls_config}
}
