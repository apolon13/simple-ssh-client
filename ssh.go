package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/shiena/ansicolor"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
)

var (
	user = flag.String("u", "", "Username")
	host = flag.String("h", "", "Hostname")
	port = flag.Int("p", 22, "Port")
	pk   = flag.String("pk", defaultKeyPath(), "Private key file")
)

func defaultKeyPath() string {
	home := os.Getenv("HOME")
	if len(home) > 0 {
		return path.Join(home, ".ssh/id_rsa")
	}
	return ""
}

func main() {
	flag.Parse()
	key, err := ioutil.ReadFile(*pk)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		panic(err)
	}

	config := &ssh.ClientConfig{
		User:            *user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		panic(err)
	}
	session, err := client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 100, 100, modes); err != nil {
		panic(err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		panic(err)
	}
	if err := session.Shell(); err != nil {
		panic(err)
	}
	go io.Copy(ansicolor.NewAnsiColorWriter(os.Stdout), stdout)
	go io.Copy(stdin, os.Stdin)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for {
			<-c
			stdin.Write([]byte("\x03"))
		}
	}()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		stdin.Write(append(scanner.Bytes(), []byte("\n")...))
	}
}
