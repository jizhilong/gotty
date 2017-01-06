package app

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/yudai/gotty/backends"
	"github.com/yudai/gotty/utils"

	"github.com/braintree/manners"
	"github.com/elazarl/go-bindata-assetfs"
	"github.com/gorilla/websocket"
	"github.com/yudai/umutex"
)

type InitMessage struct {
	Arguments string `json:"Arguments,omitempty"`
	AuthToken string `json:"AuthToken,omitempty"`
}

type App struct {
	manager backends.ClientContextManager
	options *Options

	upgrader    *websocket.Upgrader
	server      *manners.GracefulServer
	onceMutex   *umutex.UnblockingMutex
	connections int
}

type Options struct {
	Address             string                 `hcl:"address" flagName:"address" flagSName:"a" flagDescribe:"IP address to listen" default:""`
	Port                string                 `hcl:"port" flagName:"port" flagSName:"p" flagDescribe:"Port number to liten" default:"8080"`
	PermitWrite         bool                   `hcl:"permit_write" flagName:"permit-write" flagSName:"w" flagDescribe:"Permit clients to write to the TTY (BE CAREFUL)" default:"false"`
	EnableBasicAuth     bool                   `hcl:"enable_basic_auth" default:"false"`
	Credential          string                 `hcl:"credential" flagName:"credential" flagSName:"c" flagDescribe:"Credential for Basic Authentication (ex: user:pass, default disabled)" default:""`
	EnableRandomUrl     bool                   `hcl:"enable_random_url flagName:"random-url" flagSName:"r" flagDescribe:"Add a random string to the URL"" default:"false"`
	RandomUrlLength     int                    `hcl:"random_url_length" flagName:"random-url-length" flagSName:"" flagDescribe:"Random URL length" default:"8"`
	IndexFile           string                 `hcl:"index_file" flagName:"index" flagSName:"" flagDescribe:"Custom index.html file" default:""`
	EnableTLS           bool                   `hcl:"enable_tls" flagName:"tls" flagSName:"t" flagDescribe:"Enable TLS/SSL" default:"false"`
	TLSCrtFile          string                 `hcl:"tls_crt_file" flagName:"tls-crt" flagSName:"" flagDescribe:"TLS/SSL certificate file path" default:"~/.gotty.crt"`
	TLSKeyFile          string                 `hcl:"tls_key_file" flagName:"tls-key" flagSName:"" flagDescribe:"TLS/SSL key file path" default:"~/.gotty.key"`
	EnableTLSClientAuth bool                   `hcl:"enable_tls_client_auth" default:"false"`
	TLSCACrtFile        string                 `hcl:"tls_ca_crt_file" flagName:"tls-ca-crt" flagSName:"" flagDescribe:"TLS/SSL CA certificate file for client certifications" default:"~/.gotty.ca.crt"`
	EnableReconnect     bool                   `hcl:"enable_reconnect" flagName:"reconnect" flagSName:"" flagDescribe:"Enable reconnection" default:"false"`
	ReconnectTime       int                    `hcl:"reconnect_time" flagName:"reconnect-time" flagSName:"" flagDescribe:"Time to reconnect" default:"10"`
	MaxConnection       int                    `hcl:"max_connection" flagName:"max-connection" flagSName:"" flagDescribe:"Maximum connection to gotty" default:"0"`
	Once                bool                   `hcl:"once" flagName:"once" flagSName:"" flagDescribe:"Accept only one client and exit on disconnection" default:"false"`
	PermitArguments     bool                   `hcl:"permit_arguments" flagName:"permit-arguments" flagSName:"" flagDescribe:"Permit clients to send command line arguments in URL (e.g. http://example.com:8080/?arg=AAA&arg=BBB)" default:"false"`
	Preferences         HtermPrefernces        `hcl:"preferences"`
	RawPreferences      map[string]interface{} `hcl:"preferences"`
}

var Version = "0.0.13"

func New(manager backends.ClientContextManager, options *Options) (*App, error) {
	return &App{
		options: options,
		manager: manager,

		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			Subprotocols:    []string{"gotty"},
		},
		onceMutex: umutex.New(),
	}, nil
}

func CheckConfig(options *Options) error {
	if options.EnableTLSClientAuth && !options.EnableTLS {
		return errors.New("TLS client authentication is enabled, but TLS is not enabled")
	}
	return nil
}

func (app *App) Run() error {
	if app.options.PermitWrite {
		log.Printf("Permitting clients to write input to the PTY.")
	}

	if app.options.Once {
		log.Printf("Once option is provided, accepting only one client")
	}

	path := ""
	if app.options.EnableRandomUrl {
		path += "/" + generateRandomString(app.options.RandomUrlLength)
	}

	endpoint := net.JoinHostPort(app.options.Address, app.options.Port)

	wsHandler := http.HandlerFunc(app.handleWS)
	customIndexHandler := http.HandlerFunc(app.handleCustomIndex)
	authTokenHandler := http.HandlerFunc(app.handleAuthToken)
	staticHandler := http.FileServer(
		&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, Prefix: "static"},
	)

	var siteMux = http.NewServeMux()

	if app.options.IndexFile != "" {
		log.Printf("Using index file at " + app.options.IndexFile)
		siteMux.Handle(path+"/", customIndexHandler)
	} else {
		siteMux.Handle(path+"/", http.StripPrefix(path+"/", staticHandler))
	}
	siteMux.Handle(path+"/auth_token.js", authTokenHandler)
	siteMux.Handle(path+"/js/", http.StripPrefix(path+"/", staticHandler))
	siteMux.Handle(path+"/favicon.png", http.StripPrefix(path+"/", staticHandler))

	siteHandler := http.Handler(siteMux)

	if app.options.EnableBasicAuth {
		log.Printf("Using Basic Authentication")
		siteHandler = wrapBasicAuth(siteHandler, app.options.Credential)
	}

	siteHandler = wrapHeaders(siteHandler)

	wsMux := http.NewServeMux()
	wsMux.Handle("/", siteHandler)
	wsMux.Handle(path+"/ws", wsHandler)
	siteHandler = (http.Handler(wsMux))

	siteHandler = wrapLogger(siteHandler)

	scheme := "http"
	if app.options.EnableTLS {
		scheme = "https"
	}
	if app.options.Address != "" {
		log.Printf(
			"URL: %s",
			(&url.URL{Scheme: scheme, Host: endpoint, Path: path + "/"}).String(),
		)
	} else {
		for _, address := range listAddresses() {
			log.Printf(
				"URL: %s",
				(&url.URL{
					Scheme: scheme,
					Host:   net.JoinHostPort(address, app.options.Port),
					Path:   path + "/",
				}).String(),
			)
		}
	}

	server, err := app.makeServer(endpoint, &siteHandler)
	if err != nil {
		return errors.New("Failed to build server: " + err.Error())
	}
	app.server = manners.NewWithServer(
		server,
	)

	if app.options.EnableTLS {
		crtFile := utils.ExpandHomeDir(app.options.TLSCrtFile)
		keyFile := utils.ExpandHomeDir(app.options.TLSKeyFile)
		log.Printf("TLS crt file: " + crtFile)
		log.Printf("TLS key file: " + keyFile)

		err = app.server.ListenAndServeTLS(crtFile, keyFile)
	} else {
		err = app.server.ListenAndServe()
	}
	if err != nil {
		return err
	}

	log.Printf("Exiting...")

	return nil
}

func (app *App) makeServer(addr string, handler *http.Handler) (*http.Server, error) {
	server := &http.Server{
		Addr:    addr,
		Handler: *handler,
	}

	if app.options.EnableTLSClientAuth {
		caFile := utils.ExpandHomeDir(app.options.TLSCACrtFile)
		log.Printf("CA file: " + caFile)
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("Could not open CA crt file " + caFile)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("Could not parse CA crt file data in " + caFile)
		}
		tlsConfig := &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		server.TLSConfig = tlsConfig
	}

	return server, nil
}

func (app *App) handleWS(w http.ResponseWriter, r *http.Request) {
	if app.options.MaxConnection != 0 {
		if app.connections >= app.options.MaxConnection {
			log.Printf("Reached max connection: %d", app.options.MaxConnection)
			return
		}
	}
	log.Printf("New client connected: %s", r.RemoteAddr)

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	conn, err := app.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("Failed to upgrade connection: " + err.Error())
		return
	}

	_, stream, err := conn.ReadMessage()
	if err != nil {
		log.Print("Failed to authenticate websocket connection")
		conn.Close()
		return
	}
	var init InitMessage

	err = json.Unmarshal(stream, &init)
	if err != nil {
		log.Printf("Failed to parse init message %v", err)
		conn.Close()
		return
	}
	if init.AuthToken != app.options.Credential {
		log.Print("Failed to authenticate websocket connection")
		conn.Close()
		return
	}

	var queryPath string
	if app.options.PermitArguments && init.Arguments != "" {
		queryPath = init.Arguments
	} else {
		queryPath = "?"
	}

	query, err := url.Parse(queryPath)
	if err != nil {
		log.Print("Failed to parse arguments")
		conn.Close()
		return
	}
	params := query.Query()
	ctx, err := app.manager.New(params)
	if err != nil {
		log.Print("Failed to new client context")
		conn.Close()
		return
	}

	app.server.StartRoutine()

	if app.options.Once {
		if app.onceMutex.TryLock() { // no unlock required, it will die soon
			log.Printf("Last client accepted, closing the listener.")
			app.server.Close()
		} else {
			log.Printf("Server is already closing.")
			conn.Close()
			return
		}
	}

	app.connections++
	context := &clientContext{app: app, request: r, connection: conn, writeMutex: &sync.Mutex{}, ClientContext: ctx}
	context.goHandleClient()
}

func (app *App) handleCustomIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, utils.ExpandHomeDir(app.options.IndexFile))
}

func (app *App) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte("var gotty_auth_token = '" + app.options.Credential + "';"))
}

func (app *App) Exit() (firstCall bool) {
	if app.server != nil {
		firstCall = app.server.Close()
		if firstCall {
			log.Printf("Received Exit command, waiting for all clients to close sessions...")
		}
		return firstCall
	}
	return true
}

func wrapLogger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWrapper{w, 200}
		handler.ServeHTTP(rw, r)
		log.Printf("%s %d %s %s", r.RemoteAddr, rw.status, r.Method, r.URL.Path)
	})
}

func wrapHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GoTTY/"+Version)
		handler.ServeHTTP(w, r)
	})
}

func wrapBasicAuth(handler http.Handler, credential string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(token) != 2 || strings.ToLower(token[0]) != "basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoTTY"`)
			http.Error(w, "Bad Request", http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(token[1])
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if credential != string(payload) {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoTTY"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		log.Printf("Basic Authentication Succeeded: %s", r.RemoteAddr)
		handler.ServeHTTP(w, r)
	})
}

func generateRandomString(length int) string {
	const base = 36
	size := big.NewInt(base)
	n := make([]byte, length)
	for i, _ := range n {
		c, _ := rand.Int(rand.Reader, size)
		n[i] = strconv.FormatInt(c.Int64(), base)[0]
	}
	return string(n)
}

func listAddresses() (addresses []string) {
	ifaces, _ := net.Interfaces()

	addresses = make([]string, 0, len(ifaces))

	for _, iface := range ifaces {
		ifAddrs, _ := iface.Addrs()
		for _, ifAddr := range ifAddrs {
			switch v := ifAddr.(type) {
			case *net.IPNet:
				addresses = append(addresses, v.IP.String())
			case *net.IPAddr:
				addresses = append(addresses, v.IP.String())
			}
		}
	}

	return
}
