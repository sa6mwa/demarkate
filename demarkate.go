/* Demarkate https://github.com/sa6mwa/demarkate
 * Copyright 2019 SA6MWA Michel <sa6mwa@radiohorisont.se>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package demarkate

import (
  "crypto/tls"
  "net"
  "net/url"
  "net/http"
  "net/http/httputil"
  "fmt"
  "time"
  "os"
  "io"
  "strings"
  "bytes"
  golog "log"

  "golang.org/x/net/http2"
  "golang.org/x/net/http2/h2c"
  "golang.org/x/net/netutil"
  log "github.com/sirupsen/logrus"
  "github.com/kelseyhightower/envconfig"
  "github.com/gobwas/glob"
  "github.com/sa6mwa/demarkate/pemloader"
  "github.com/sa6mwa/demarkate/custom"
)

// version gets replaced by -ldflags "-X github.com/sa6mwa/demarkate.version=..." in Makefile
var version = "v0.0"

// envconfig prefix
var EnvconfigPrefix = "DEMARKATE"


// This is a fake io.Writer for use with log.Logger to logrus. Inspired by
// https://stackoverflow.com/a/52964506
type logrusWriter struct {
  io.Writer
}
// logrusWriter pointer receiver, a Write wrapper to logrus
func (m *logrusWriter) Write(p []byte) (n int, err error) {
  // uncommented since we do not want to write anything
  //n, err = m.Writer.Write(p)
  //return
  log.Error(strings.TrimSpace(string(p)))
  return len(p), nil
}

// Stores a go standard Logger using the logrusWriter wrapper
var logWrapper *golog.Logger

func init() {
  // log.Logger for http ErrorLog using io.Writer wrapper to use logrus instead
  logWrapper = golog.New(&logrusWriter{}, "", golog.LstdFlags)
  // configure logrus to output json formatted logs
  log.SetFormatter(UTCFormatter{&log.JSONFormatter{
    FieldMap: log.FieldMap{
      log.FieldKeyTime: "timestamp",
      log.FieldKeyLevel: "level",
      log.FieldKeyMsg: "message",
    },
  }})
  log.SetOutput(os.Stdout)
  log.SetLevel(log.InfoLevel)
  log.AddHook(&hook{})
}
// https://stackoverflow.com/a/40502637
type UTCFormatter struct {
    log.Formatter
}
func (u UTCFormatter) Format(e *log.Entry) ([]byte, error) {
    e.Time = e.Time.UTC()
    return u.Formatter.Format(e)
}
type hook struct{}
func (h *hook) Levels() []log.Level {
  return log.AllLevels
}
func (h *hook) Fire(e *log.Entry) error {
  // omit keys with empty values
  for k, v := range e.Data {
    switch r := v.(type) {
      case string:
        if r == "" {
          delete(e.Data, k)
          continue
        }
      case []string:
        if len(r) == 0 {
          delete(e.Data, k)
        }
    }
  }
  return nil
}


// New() Config struct, envconfig prefix is DEMARKATE_, e.g
// DEMARKATE_LISTEN_TO=":1337" DEMARKATE_SELF_SIGN="true"
type Config struct {
  Protocol string `envconfig:"PROTOCOL"`
  ListenTo []string `envconfig:"LISTEN_TO"`
  MaxConns int `envconfig:"MAX_CONNS"`
  MaxIdleConns int `envconfig:"MAX_IDLE_CONNS"`
  Timeout time.Duration `envconfig:"TIMEOUT"`
  ReadHeaderTimeout time.Duration `envconfig:"READHEADERTIMEOUT"`
  ReadTimeout time.Duration `envconfig:"READTIMEOUT"`
  WriteTimeout time.Duration `envconfig:"WRITETIMEOUT"`
  IdleTimeout time.Duration `envconfig:"IDLETIMEOUT"`
  Backend string `envconfig:"BACKEND"`
  Backends []string `envconfig:"BACKENDS"`
  BackendType string `envconfig:"BACKEND_TYPE"`
  BackendTimeout time.Duration `envconfig:"BACKEND_TIMEOUT"`
  CertFiles []string `envconfig:"CERT_FILES"`
  SelfSign bool `envconfig:"SELF_SIGN"`
  Organization string `envconfig:"SELF_SIGN_ORG"`
  CommonName string `envconfig:"SELF_SIGN_CN"`
  Log bool `envconfig:"LOG"`
  UsageOnSyntaxError bool `envconfig:"USAGE"`
  BackendStructs []BackendStruct `ignored:"true"`
  URL *url.URL `ignored:"true"`
}
type BackendStruct struct {
  Filter string
  Target string
  URL *url.URL
  HostGlob glob.Glob
  Path string
}


type Option func(cnf *Config)

func New(opts ...Option) Config {
  cnf := &Config{
    Protocol: "tcp",
    ListenTo: []string{},
    MaxConns: 500,
    MaxIdleConns: 100,
    Timeout: 5 * time.Minute,
    ReadHeaderTimeout: 30 * time.Second,
    ReadTimeout: 30 * time.Second,
    WriteTimeout: 30 * time.Second,
    IdleTimeout: 60 * time.Second,
    Backend: "",
    Backends: []string{},
    BackendType: "h2c",
    BackendTimeout: 5 * time.Second,
    CertFiles: []string{},
    SelfSign: false,
    Organization: "Globex Corporation",
    CommonName: "localhost",
    Log: true,
    UsageOnSyntaxError: true,
  }
  for _, opt := range opts {
    opt(cnf)
  }
  if ! cnf.SelfSign {
    cnf.Organization = ""
    cnf.CommonName = ""
  }
  for _, b := range cnf.Backends {
    backendPair := strings.SplitN(b, "=", 2)
    if len(backendPair) == 2 {
      backend_url, err := url.Parse(backendPair[1])
      if err == nil {
        cnf.BackendStructs = append(cnf.BackendStructs, BackendStruct{
          Filter: backendPair[0],
          Target: backendPair[1],
          URL: backend_url,
        })
      } else {
        log.Error("unable to url.Parse %s", backendPair[1])
      }
    }
  }
  // We only support binding two ports, first is potentially http2 with tls,
  // second is always h2c or http1 with h2c upgrade (unencrypted)
  if len(cnf.ListenTo) > 2 {
    cnf.ListenTo = cnf.ListenTo[:2]
  }
  return *cnf
}


func OnlyTCP4() Option {
  return func(cnf *Config) {
    cnf.Protocol = "tcp4"
  }
}
func OnlyTCP6() Option {
  return func(cnf *Config) {
    cnf.Protocol = "tcp6"
  }
}
func ListenTo(socket_address string) Option {
  return func(cnf *Config) {
    cnf.ListenTo = append(cnf.ListenTo, socket_address)
  }
}
func MaxConns(conns int) Option {
  return func(cnf *Config) {
    cnf.MaxConns = conns
  }
}
func Timeout(timeout time.Duration) Option {
  return func(cnf *Config) {
    cnf.Timeout = timeout
  }
}
func Backend(backend string) Option {
  return func(cnf *Config) {
    cnf.Backend = backend
  }
}
func BackendType(backendType string) Option {
  return func(cnf *Config) {
    cnf.BackendType = backendType
  }
}
func CertFiles(pemFiles []string) Option {
  return func(cnf *Config) {
    cnf.CertFiles = pemFiles
  }
}
func SelfSign() Option {
  return func(cnf *Config) {
    cnf.SelfSign = true
  }
}
func Organization(org string) Option {
  return func(cnf *Config) {
    cnf.Organization = org
  }
}
func CommonName(cn string) Option {
  return func(cnf *Config) {
    cnf.CommonName = cn
  }
}
func EnvConfig() Option {
  return func(cnf *Config) {
    err := envconfig.Process(EnvconfigPrefix, cnf)
    if err != nil {
      log.Fatal(err.Error())
    }
  }
}
func UsageOnSyntaxError(v bool) Option {
  return func(cnf *Config) {
    cnf.UsageOnSyntaxError = v
  }
}


/* wrapped logging functions for convenience, e.g: demarkate.Info("hello world") */
func Info(format string, v ...interface{}) {
  log.Info(fmt.Sprintf(format, v...))
}
func Printf(format string, v ...interface{}) {
  log.Info(fmt.Sprintf(format, v...))
}
func Warn(format string, v ...interface{}) {
  log.Warn(fmt.Sprintf(format, v...))
}
func Warning(format string, v ...interface{}) {
  log.Warn(fmt.Sprintf(format, v...))
}
func Error(format string, v ...interface{}) {
  log.Error(fmt.Sprintf(format, v...))
}
func Errorf(format string, v ...interface{}) {
  log.Error(fmt.Sprintf(format, v...))
}
func Debug(format string, v ...interface{}) {
  log.Debug(fmt.Sprintf(format, v...))
}
func Fatal(format string, v ...interface{}) {
  log.Fatal(fmt.Sprintf(format, v...))
}
func Panic(format string, v ...interface{}) {
  log.Panic(fmt.Sprintf(format, v...))
}


// Used to store the signature of which NewSingleHostReverseProxy function to
// use depending on the value of DEMARKATE_BACKEND_TYPE.
//type SingleHostReverseProxyFunc func(*url.URL)(*httputil.ReverseProxy)


func isOneOf(s string, mustBeOneOf... string) error {
  // string s must be one of mustBeOneOf
  for _, k := range mustBeOneOf {
    if s == k {
      return nil
    }
  }
  return fmt.Errorf("%s does not contain %v", s, mustBeOneOf)
}


// from github.com/golang/go/src/net/http/httputil/reverseproxy.go
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func removeDupSlashes(s string) string {
  var buf bytes.Buffer
  var last rune
  for i, r := range s {
    if r != '/' || r != last || i == 0 {
      buf.WriteRune(r)
      last = r
    }
  }
  return buf.String()
}

func NewReverseProxy(cnf *Config) (*httputil.ReverseProxy) {
  var director func(*http.Request)
  backendType := strings.ToLower(cnf.BackendType)
  // make sure we know the backend type
  err := isOneOf(backendType, "h2c", "http2c", "http2", "http", "http1", "http11", "http1.1")
  if err != nil {
    return nil
  }
  // iterate over backend_type and change what's necessary
  switch backendType {
    case "h2c", "http2c":
      // prep h2c endpoints
      for i := range cnf.BackendStructs {
        if ! strings.Contains(cnf.BackendStructs[i].URL.Host, ":") {
          switch strings.ToLower(cnf.BackendStructs[i].URL.Scheme) {
            case "http":
              cnf.BackendStructs[i].URL.Host = cnf.BackendStructs[i].URL.Host + ":80"
            case "https":
              cnf.BackendStructs[i].URL.Host = cnf.BackendStructs[i].URL.Host + ":443"
            case "http-alt":
              cnf.BackendStructs[i].URL.Host = cnf.BackendStructs[i].URL.Host + ":8080"
            case "gopher":
              cnf.BackendStructs[i].URL.Host = cnf.BackendStructs[i].URL.Host + ":70"
          }
        }
        // Enforce https to use DialTLS transport for clear-text http2.
        cnf.BackendStructs[i].URL.Scheme = "https"
      }
  }

  if len(cnf.BackendStructs) == 1 && cnf.BackendStructs[0].Filter == "/" {
    log.Infof("Single backend configured, setting up single host reverse proxy for %s", cnf.BackendStructs[0].Target)
    // setup a director similar to httputil.NewSingleHostReverseProxy
    b := cnf.BackendStructs[0]
    director = func(req *http.Request) {
      req.URL.Scheme = b.URL.Scheme
      req.URL.Host = b.URL.Host
      origURLpath := req.URL.Path
      req.URL.Path = singleJoiningSlash(b.URL.Path, req.URL.Path)
      if b.URL.RawQuery == "" || req.URL.RawQuery == "" {
        req.URL.RawQuery = b.URL.RawQuery + req.URL.RawQuery
      } else {
        req.URL.RawQuery = b.URL.RawQuery + "&" + req.URL.RawQuery
      }
      if _, ok := req.Header["User-Agent"]; !ok {
        // explicitly disable User-Agent so it's not set to default value
        req.Header.Set("User-Agent", "")
      }
      log.WithFields(log.Fields{
        "request_uri": req.RequestURI,
        "host": req.Host,
        "remote_addr": req.RemoteAddr,
        "method": req.Method,
        "protocol": req.Proto,
        "close": req.Close,
        "receiver": req.URL.Scheme + "://" + req.URL.Host + req.URL.Path,
        "filter": b.Filter,
        "backend": b.Target,
        "user-agent": req.Header.Get("User-Agent"),
      }).Infof("%s%s DE %s QSO %s://%s%s", req.Host, origURLpath, req.RemoteAddr, req.URL.Scheme, req.URL.Host, req.URL.Path)
    }
  } else {
    // else it's a multi-host, multi-path director
    for i := range cnf.BackendStructs {
      // compile host glob and path (path can not be a glob unfortunately)
      host := "*"
      path := ""
      if len(cnf.BackendStructs[i].Filter) > 0 {
        if cnf.BackendStructs[i].Filter[0] == '/' {
          // interpret as a path from any host
          path = "/" + strings.TrimLeft(removeDupSlashes(cnf.BackendStructs[i].Filter), "/")
        } else {
          // interpret as a host/path match or possible only host
          s := strings.SplitN(cnf.BackendStructs[i].Filter, "/", 2)
          host = s[0]
          if len(s) > 1 {
            path = "/" + strings.TrimLeft(removeDupSlashes(s[1]), "/")
          }
        }
      }
      cnf.BackendStructs[i].HostGlob = glob.MustCompile(host)
      cnf.BackendStructs[i].Path = path
    }
    // multihost, multipath director
    director = func(req *http.Request) {
      reqHost := strings.SplitN(req.Host, ":", 2)[0]
      for _, b := range cnf.BackendStructs {
        if b.HostGlob.Match(reqHost) && strings.HasPrefix(req.URL.Path, b.Path) {
          req.URL.Scheme = b.URL.Scheme
          req.URL.Host = b.URL.Host
          origURLpath := req.URL.Path
          pathRemainder := strings.TrimLeft(req.URL.Path, b.Path)
          if pathRemainder == "" {
            req.URL.Path = b.URL.Path
          } else {
            req.URL.Path = singleJoiningSlash(b.URL.Path, pathRemainder)
          }
          log.Info("new req.URL.Path: " + req.URL.Path)
          if b.URL.RawQuery == "" || req.URL.RawQuery == "" {
            req.URL.RawQuery = b.URL.RawQuery + req.URL.RawQuery
          } else {
            req.URL.RawQuery = b.URL.RawQuery + "&" + req.URL.RawQuery
          }
          if _, ok := req.Header["User-Agent"]; !ok {
            // explicitly disable User-Agent so it's not set to default value
            req.Header.Set("User-Agent", "")
          }
          log.WithFields(log.Fields{
            "request_uri": req.RequestURI,
            "host": req.Host,
            "remote_addr": req.RemoteAddr,
            "method": req.Method,
            "protocol": req.Proto,
            "close": req.Close,
            "receiver": req.URL.Scheme + "://" + req.URL.Host + req.URL.Path,
            "filter": b.Filter,
            "backend": b.Target,
            "user-agent": req.Header.Get("User-Agent"),
          }).Infof("%s%s DE %s QSO %s://%s%s", req.Host, origURLpath, req.RemoteAddr, req.URL.Scheme, req.URL.Host, req.URL.Path)
          return
        }
      }
      log.Error("request did not match a backend filter!")
    }
  }

  // director has been set up, get a ReverseProxy with our director and
  // io.Writer log wrapper
  proxy := &httputil.ReverseProxy{ Director: director, ErrorLog: logWrapper }

  // add type specific dialers and transports
  switch strings.ToLower(backendType) {
    case "h2c", "http2c":
      // H2c (cleartext http2) ReverseProxy
      // we ignore tls.Config in our custom dialer to always make clear-text connections
      dial := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
        d := net.Dialer{ Timeout: cnf.BackendTimeout }
        return d.Dial(network, addr)
      }
      transport := &http2.Transport{
        // AllowHTTP true is not the same as bypassing DialTLS with a cleartext TCP
        // dialer (commented out)...
        // AllowHTTP: true,
        DialTLS: dial,
      }
      proxy.Transport = transport
    case "http2":
      // HTTP/2 TLS ReverseProxy, uses http2.Transport instead of
      // http.Transport (you will probably want "http" below for http2 in most
      // cases)
      tlscc := &tls.Config{
        InsecureSkipVerify: true,
      }
      transport := &http2.Transport{
        TLSClientConfig: tlscc,
      }
      proxy.Transport = transport
    case "http", "http1", "http11", "http1.1":
      // HTTP/1.1 and HTTP/2 ReverseProxy
      tlscc := &tls.Config{
        InsecureSkipVerify: true,
      }
      transport := &http.Transport{
        TLSClientConfig: tlscc,
        TLSHandshakeTimeout: cnf.BackendTimeout,
        MaxIdleConns: cnf.MaxIdleConns,
        IdleConnTimeout: cnf.IdleTimeout,
        ExpectContinueTimeout: 1 * time.Second,
        DialContext: (&net.Dialer{ Timeout: cnf.BackendTimeout, KeepAlive: 30 * time.Second, DualStack: true }).DialContext,
      }
      proxy.Transport = transport
    default:
      log.Fatalf("backend type %s not supported", backendType)
  }
  return proxy
}



func Usage() {
  usageMsg := `Demarkate Copyright 2019 SA6MWA Michel <sa6mwa@radiohorisont.se>
https://github.com/sa6mwa/demarkate

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Usage: DEMARKATE_LISTEN_TO=":port" DEMARKATE_BACKEND="http://name:port" [...] %s

Demarkate is a HTTP/2, HTTP/1.1 with h2c upgrade, and HTTP2C (cleartext)
reverse proxy to handle requests to a single H2c, HTTP/2 or HTTP/1.1 endpoint
(clear or TLS). It was designed as an internal reverse proxy for gRPC between
applications that do not maintain their own certificates or TLS settings and
was intended to run as a pod in Kubernetes/Openshift.

This program is configured using environment variables prefixed by DEMARKATE_.
It runs in the foreground and prints json-formatted logs to stdout (to be
consumed by e.g fluentd).

  DEMARKATE_PROTOCOL      net.Listen protocol, e.g: "tcp" (default), "tcp4"
  DEMARKATE_LISTEN_TO     net.Listen address, e.g: ":8080". This can be 2
                          listeners separated by comma (,). The 2nd listener
                          always serves an unencrypted (with h2c upgrade) proxy
                          while the 1st listener uses TLS if you choose to.
                          Example: ":8443,:8080"
  DEMARKATE_MAX_CONNS     Maximum number of simultaneous connections to the
                          listener (proxy frontend), default is 500.
  DEMARKATE_MAX_IDLE_CONNS
                          Maximum number of idle connections.
  DEMARKATE_TIMEOUT       Handler timeout of each request, sets the timeout of
                          http.TimeoutHandler. Default 5 minutes.
  DEMARKATE_READHEADERTIMEOUT
  DEMARKATE_READTIMEOUT
  DEMARKATE_WRITETIMEOUT
  DEMARKATE_IDLETIMEOUT
                          http.Server{} timeouts. Some strict defaults are
                          provided, but you have the possibility to customize
                          the proxy frontend server timeouts using these
                          variables
  DEMARKATE_BACKEND       URL of backend endpoint, e.g: "http://mysvc:12345".
                          Preserved for backwards compatibility.
  DEMARKATE_BACKENDS      Multihost, multipath reverse proxy. Key=value pairs
                          of host/path (filter) and destination backend URL as
                          a list where rules are separated by comma (,).  The
                          list is processed top down and when a filter matches
                          (both host and path, unless host is empty) it directs
                          the proxy towards the associated upstream.  Filter
                          can be host/path/subpath or simply "hostname.tld".
                          The hostname part can contain globs (not the path
                          part), for example, "*company.*" which will match
                          anycompany.anydomain.
                          Examples:
                          "*altsite.com=http://alt.net:8080,/=http://default"
                          If host header in request ends with altsite.com all
                          requests (as path is empty or /) will go towards
                          http://alt.net:8080. If the host header does not
                          match it continues to the single slash filter, which
                          will match anything, thus the default site.
                          Example: all /status requests to the same backend,
                          but if host starts with "api." and has path /special,
                          direct it to a special api backend, otherwise direct
                          all other api requests to the api backend on port
                          8080, unless host starts with www, request should go
                          to the web host on port 8081:
                          "/status=http://status:1234,api.*/special=http://sapi,
                          api.*=http://api:8080,www.*=http://web:8081"
                          If there is no match, proxy will return 502 Bad
                          Gateway.
  DEMARKATE_BACKEND_TYPE  Choose single reverse proxy client type:
                          "h2c" (default), "http2", or "http" (for 2 and 1.1).
                          Currently, this configures all backends to be of the
                          same type, there is no multi-type support yet.
  DEMARKATE_BACKEND_TIMEOUT
                          net.Dial timeout to the backend, default is 5
                          seconds.
  DEMARKATE_CERT_FILES    Comma separated list of PEM, CRT or KEY files. Will
                          try to load both certificate and private key from
                          each file (you can combine cert and key into a single
                          pem file or keep them in separate files)
                          e.g: DEMARKATE_CERT_FILES="server.crt,server.key"
  DEMARKATE_SELF_SIGN     Generate a self-signed certificate, "true" or "false"
                          (default is "false")
  DEMARKATE_SELF_SIGN_ORG Subject Organization of self-signed certificate
  DEMARKATE_SELF_SIGN_CN  Subject CommonName of self-signed certificate
                          (usually the domain name)
  DEMARKATE_LOG           Log or not ("true" or "false", default is "true")
  DEMARKATE_USAGE         Print usage on syntax error ("true" by default), will
                          break json logging (set to "false" to disable usage
                          printing)
`
  fmt.Printf(usageMsg, os.Args[0])
}



func Start(cnf *Config) error {
  var proxy *httputil.ReverseProxy
  h2typeString := "http2c (cleartext!)"
  if len(cnf.CertFiles) > 0 {
    h2typeString = "http2 (tls)"
  } else {
    if cnf.SelfSign {
      h2typeString = "http2 (tls with generated self-signed certificate)"
    }
  }

  // initial assertions
  errors := []error{}
  if len(cnf.ListenTo) == 0 {
    errors = append(errors, fmt.Errorf(`missing listen address, e.g: DEMARKATE_LISTEN_TO=":8080" %s`, os.Args[0]))
  }

  if len(cnf.Backends) > 0 {
    if cnf.Backend != "" {
      errors = append(errors, fmt.Errorf("you can not use both DEMARKATE_BACKEND and DEMARKATE_BACKENDS, choose one, BACKEND for single host reverse proxy or BACKENDS for multiple backends"))
    }
  } else {
    if cnf.Backend == "" {
      errors = append(errors, fmt.Errorf("missing backend URL, hint: environment variable DEMARKATE_BACKEND"))
    } else {
      backend_url, err := url.Parse(cnf.Backend)
      if err != nil {
        errors = append(errors, err)
      } else {
        cnf.BackendStructs = append(cnf.BackendStructs, BackendStruct{
          Filter: "/",
          Target: cnf.Backend,
          URL: backend_url,
        })
      }
    }
  }

  proxy = NewReverseProxy(cnf)
  if proxy == nil {
    errors = append(errors, fmt.Errorf("could not create new reverse proxy, unknown backend type?"))
  }

  if cnf.UsageOnSyntaxError && len(errors) > 0 {
    Usage()
  }
  if len(errors) > 0 {
    for i, err := range errors {
      log.Error(err.Error())
      if i == len(errors) - 1 {
        // return the last err
        return err
      }
    }
  }

  startlog := log.WithFields(log.Fields{
      EnvconfigPrefix + "_PROTOCOL": cnf.Protocol,
      EnvconfigPrefix + "_LISTEN_TO": cnf.ListenTo,
      EnvconfigPrefix + "_MAX_CONNS": cnf.MaxConns,
      EnvconfigPrefix + "_MAX_IDLE_CONNS": cnf.MaxIdleConns,
      EnvconfigPrefix + "_TIMEOUT": cnf.Timeout.String(),
      EnvconfigPrefix + "_READHEADERTIMEOUT": cnf.ReadHeaderTimeout.String(),
      EnvconfigPrefix + "_READTIMEOUT": cnf.ReadTimeout.String(),
      EnvconfigPrefix + "_WRITETIMEOUT": cnf.WriteTimeout.String(),
      EnvconfigPrefix + "_IDLETIMEOUT": cnf.IdleTimeout.String(),
      EnvconfigPrefix + "_BACKEND": cnf.Backend,
      EnvconfigPrefix + "_BACKENDS": cnf.Backends,
      EnvconfigPrefix + "_BACKEND_TYPE": cnf.BackendType,
      EnvconfigPrefix + "_BACKEND_TIMEOUT": cnf.BackendTimeout.String(),
      EnvconfigPrefix + "_CERT_FILES": cnf.CertFiles,
      EnvconfigPrefix + "_SELF_SIGN": cnf.SelfSign,
      EnvconfigPrefix + "_SELF_SIGN_ORG": cnf.Organization,
      EnvconfigPrefix + "_SELF_SIGN_CN": cnf.CommonName,
      EnvconfigPrefix + "_LOG": cnf.Log,
      "version": version,
  })
  startlog.Info("Initializing demarkate")

  /** tlsConfig from https://gist.github.com/denji/12b3a568f092ab951456
    */
  tlsConfig := &tls.Config{
    MinVersion:       tls.VersionTLS12,
    CurvePreferences: []tls.CurveID{
      tls.CurveP521,
      tls.CurveP384,
      tls.CurveP256,
      tls.X25519, // Go 1.8 only
    },
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
      // unfortunately, the two aes-128 below need to be first for http2
      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    },
  }

  handler := custom.TimeoutHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    log.WithFields(log.Fields{
      "file": "access.log",
      "remote_addr": r.RemoteAddr,
      "method": r.Method,
      "request_uri": r.RequestURI,
      "protocol": r.Proto,
      "close": r.Close,
      "content_length": r.ContentLength,
    }).Infof("%s DE %s", r.RequestURI, r.RemoteAddr)
    proxy.ServeHTTP(w, r)
  }), cnf.Timeout, "")

  srv := &http.Server{
    ReadHeaderTimeout: cnf.ReadHeaderTimeout,
    ReadTimeout: cnf.ReadTimeout,
    WriteTimeout: cnf.WriteTimeout,
    IdleTimeout: cnf.IdleTimeout,
    TLSConfig: tlsConfig,
    Handler: handler,
    ErrorLog: logWrapper,
  }

  log.Info(fmt.Sprintf("Starting demarkate %s proxy on address %s (%s)", h2typeString, strings.Join(cnf.ListenTo, ", "), cnf.Protocol))

  lis, err := net.Listen(cnf.Protocol, cnf.ListenTo[0])
  if err != nil {
    log.Errorf("Can not bind %s: %s", cnf.ListenTo[0], err.Error())
    return err
  }
  defer lis.Close()
  // Limit simultaneous connections to DEMARKATE_MAX_CONNS
  lis = netutil.LimitListener(lis, cnf.MaxConns)

  var lis2 net.Listener
  if len(cnf.ListenTo) == 2 {
    var err error
    lis2, err = net.Listen(cnf.Protocol, cnf.ListenTo[1])
    if err != nil {
      log.Errorf("Can not bind %s", cnf.ListenTo[1], err.Error())
      return err
    }
    defer lis2.Close()
    // Limit simultaneous connections to 2nd listener to DEMARKATE_MAX_CONNS
    // aswell. TODO: Do we need a separate max conns setting?
    lis2 = netutil.LimitListener(lis2, cnf.MaxConns)
  }

  var cert *tls.Certificate
  if len(cnf.CertFiles) < 1 {
    if cnf.SelfSign {
      cert, err = pemloader.GenerateSelfSignedCert(cnf.Organization, cnf.CommonName)
      if err != nil {
        log.Error(err.Error())
        return err
      }
    } else {
      // Start a H2C server, cleartext HTTP2
      h2srv := &http2.Server{}
      srv.Handler = h2c.NewHandler(handler, h2srv)
      if len(cnf.ListenTo) == 2 {
        // start 2nd listener first
        go srv.Serve(lis2)
      }
      return srv.Serve(lis)
    }
  } else {
    cert, err = pemloader.FromMultipleFiles(cnf.CertFiles)
    if err != nil {
      log.Error(err.Error())
      return err
    }
  }
  // add certificate to tls.Config
  tlsConfig.Certificates = []tls.Certificate{ *cert }

  // start 2nd server first, if specified, as a h2c (cleartext) server
  if len(cnf.ListenTo) == 2 {
    h2srv := &http2.Server{}
    srv2 := srv
    srv2.Handler = h2c.NewHandler(handler, h2srv)
    go srv2.Serve(lis2)
  }
  // Start a HTTPS/HTTP2 server
  return srv.ServeTLS(lis, "" ,"")
}
