package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var uncatchRecover = func() {
	if r := recover(); r != nil {
		log.Println("Uncatched error:", r, string(debug.Stack()))
	}
}
var CONNECT = []byte("CONNECT")

var removeHeaders = []string{
	// "Connection",          // Connection
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	// "Keep-Alive",          // Keep-Alive
	"Proxy-Authenticate",  // Proxy-Authenticate
	"Proxy-Authorization", // Proxy-Authorization
	// "Te",                  // canonicalized version of "TE"
	// "Trailer",             // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	// "Transfer-Encoding",   // Transfer-Encoding
	// "Upgrade", // Upgrade
}

var connTimeout = 7 * time.Second
var readTimeout = 5 * time.Second

var tcpDialer = &net.Dialer{
	Timeout:   connTimeout,
	DualStack: true,
	KeepAlive: time.Minute,
}

var httpClient = &fasthttp.Client{
	DialDualStack:                 true,
	DisablePathNormalizing:        true,
	DisableHeaderNamesNormalizing: true,
	NoDefaultUserAgentHeader:      true,
	ReadBufferSize:                8 * 1024,
	ReadTimeout:                   readTimeout,
	Dial: func(addr string) (net.Conn, error) {
		return tcpDialer.Dial("tcp", addr)
	},
}

func mustProxify(hostname string) bool {
	for _, t := range targets {
		if t == hostname || (t[0] == '*' && strings.HasSuffix(hostname, t[1:])) {
			return true
		}
	}
	return false
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	defer uncatchRecover()

	host := string(ctx.Request.URI().Host())
	if len(host) == 0 {
		host = string(ctx.Host())
	}

	if len(host) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		log.Println("Reject: Empty host")
		return
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if err1, ok := err.(*net.AddrError); ok && strings.Contains(err1.Err, "missing port") {
			hostname, port, err = net.SplitHostPort(host + ":80")
		}
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			log.Println("Reject: Invalid host", host, err)
			return
		}
	}

	// https handler
	if bytes.Equal(ctx.Method(), CONNECT) {
		err := httpsHandler(ctx, hostname, port)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			log.Println("httpsHandler:", string(ctx.Request.Host()), err)
		}
		return
	}

	// http handler
	for _, v := range removeHeaders {
		ctx.Request.Header.Del(v)
	}
	// TODO: log http requests
	err = httpClient.DoTimeout(&ctx.Request, &ctx.Response, 60*time.Second)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		log.Println("httpHandler:", string(ctx.Request.Host()), err)
	}
	logReqResp(false, &ctx.Request, &ctx.Response)
}

type TimeoutReader struct {
	net.Conn
}

func (rd *TimeoutReader) Read(buf []byte) (int, error) {
	rd.Conn.SetReadDeadline(time.Now().Add(readTimeout))
	return rd.Conn.Read(buf)
}

func forwardAndLog(remoteConn net.Conn, localConn net.Conn) {
	localRead := bufio.NewReaderSize(localConn, 8*1024)
	remoteRead := bufio.NewReaderSize(remoteConn, 8*1024)

	// localWrite := bufio.NewWriter(localConn)
	// remoteWrite := bufio.NewWriter(remoteConn)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	var err error
	for {
		req.Reset()
		err = req.Read(localRead)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Println("Read local:", err)
			return
		}

		_, err = req.WriteTo(remoteConn)
		if err != nil {
			log.Println("Write remote:", err)
			return
		}
		// remoteWrite.Flush()
		resp.Reset()

		upgrade := req.Header.Peek("Upgrade")
		if len(upgrade) != 0 {
			if hasToken(string(req.Header.Peek("Upgrade")), "websocket") && hasToken(string(req.Header.Peek("Connection")), "upgrade") {
				log.Println("Upgrade", string(req.Header.Peek("Upgrade")))
				go io.Copy(remoteConn, localRead)
				io.Copy(localConn, remoteRead)
				return
			}
			resp.Header.SetStatusCode(500)
		} else {
			err = resp.Read(remoteRead)
			if err != nil && err != io.EOF {
				log.Println("Read remote:", err)
				return
			}
		}
		// log req
		logReqResp(true, req, resp)

		_, err = resp.WriteTo(localConn)
		if err != nil {
			log.Println("Write local:", err)
			return
		}
		// localWrite.Flush()
	}
}

func httpsHandler(ctx *fasthttp.RequestCtx, hostname, port string) (err error) {

	remoteConn, err := tcpDialer.Dial("tcp", "["+hostname+"]:"+port)
	if err != nil {
		// log.Println("remoteConn:", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		return
	}

	// raw proxy
	if !mustProxify(hostname) {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.Response.Header.Set("Connection", "keep-alive")
		ctx.Response.Header.Set("Keep-Alive", "timeout=120, max=5")

		ctx.Hijack(func(clientConn net.Conn) {
			go io.Copy(clientConn, remoteConn)
			io.Copy(remoteConn, clientConn)
			clientConn.Close()
			remoteConn.Close()
		})
		return
	}

	// mitm proxy
	remoteConnUnwrap := tls.Client(remoteConn, &tls.Config{
		ServerName: hostname,
		/*
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return nil
			},
		// */
	})
	err = remoteConnUnwrap.Handshake()
	if err != nil {
		// log.Println("remoteConnUnwrap:", err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		remoteConn.Close()
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=120, max=5")

	ctx.Hijack(func(clientConn net.Conn) {
		tlsConfig, err := getTLSConfig(hostname)
		if err != nil {
			log.Println("getTLSConfig:", hostname, err)
			clientConn.Close()
			remoteConn.Close()
			return
		}
		clientConnUnwrap := tls.Server(clientConn, tlsConfig)
		err = clientConnUnwrap.Handshake()
		if err != nil {
			// log.Println("Client handshake", hostname, err)
			clientConn.Close()
			remoteConn.Close()
			return
		}
		// TODO: log https requests
		forwardAndLog(remoteConnUnwrap, clientConnUnwrap)
		time.Sleep(time.Second)
		clientConn.Close()
		remoteConn.Close()
	})
	return nil
}

type TargetArg []string

func (f *TargetArg) String() string {
	return strings.Join(*f, ";")
}
func (f *TargetArg) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var targets TargetArg
var listen = flag.String(`listen`, `:11337`, `Listen address. Eg: :8443; unix:/tmp/proxy.sock`)

func main() {
	flag.Var(&targets, "target", "Target to monitor/log/mitm. Eg: *.target.vn")
	flag.Parse()

	// Server
	var err error
	var ln net.Listener
	if strings.HasPrefix(*listen, `unix:`) {
		unixFile := (*listen)[5:]
		os.Remove(unixFile)
		ln, err = net.Listen(`unix`, unixFile)
		os.Chmod(unixFile, os.ModePerm)
		log.Println(`Listening:`, unixFile)
	} else {
		ln, err = net.Listen(`tcp`, *listen)
		log.Println(`Listening:`, ln.Addr().String())
	}
	if err != nil {
		log.Panicln(err)
	}

	srv := &fasthttp.Server{
		// ErrorHandler: nil,
		Handler:               requestHandler,
		NoDefaultServerHeader: true, // Don't send Server: fasthttp
		// Name: "nginx",  // Send Server header
		ReadBufferSize:                2 * 4096, // Make sure these are big enough.
		WriteBufferSize:               4096,
		ReadTimeout:                   5 * time.Second,
		WriteTimeout:                  time.Second,
		IdleTimeout:                   time.Minute, // This can be long for keep-alive connections.
		DisableHeaderNamesNormalizing: false,       // If you're not going to look at headers or know the casing you can set this.
		// NoDefaultContentType: true, // Don't send Content-Type: text/plain if no Content-Type is set manually.
		MaxRequestBodySize: 200 * 1024 * 1024, // 200MB
		DisableKeepalive:   false,
		KeepHijackedConns:  false,
		// NoDefaultDate: len(*staticDir) == 0,
		ReduceMemoryUsage: true,
		TCPKeepalive:      true,
		// TCPKeepalivePeriod: 10 * time.Second,
		// MaxRequestsPerConn: 1000,
		// MaxConnsPerIP: 20,
	}
	log.Panicln(srv.Serve(ln))
}
