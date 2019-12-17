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
  golog "log"

  "golang.org/x/net/http2"
  "golang.org/x/net/http2/h2c"
  log "github.com/sirupsen/logrus"
  "github.com/kelseyhightower/envconfig"
  "github.com/sa6mwa/demarkate/pemloader"
)

// version gets replaced by -ldflags "-X github.com/sa6mwa/demarkate.version=..." in Makefile
var version = "v0.0"



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
/* https://stackoverflow.com/a/40502637 */
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
    if s, ok := v.(string); ok {
      if s == "" {
        delete(e.Data, k)
        continue
      }
    }
  }
  return nil
}



/* New() Config struct, envconfig prefix is DEMARKATE_, e.g
 * DEMARKATE_LISTEN_TO=":1337" DEMARKATE_SELF_SIGN="true"
 */
type Config struct {
  Protocol string `envconfig:"PROTOCOL"`
  ListenTo string `envconfig:"LISTEN_TO"`
  Backend string `envconfig:"BACKEND"`
  BackendType string `envconfig:"BACKEND_TYPE"`
  CertFiles []string `envconfig:"CERT_FILES"`
  SelfSign bool `envconfig:"SELF_SIGN"`
  Organization string `envconfig:"SELF_SIGN_ORG"`
  CommonName string `envconfig:"SELF_SIGN_CN"`
  Log bool `envconfig:"LOG"`
  UsageOnSyntaxError bool `envconfig:"USAGE"`
}

type Option func(cnf *Config)

func New(opts ...Option) Config {
  cnf := Config{
    Protocol: "tcp",
    ListenTo: ":8080",
    Backend: "",
    BackendType: "h2c",
    CertFiles: []string{},
    SelfSign: false,
    Organization: "Globex Corporation",
    CommonName: "localhost",
    Log: true,
    UsageOnSyntaxError: true,
  }
  for _, opt := range opts {
    opt(&cnf)
  }
  if ! cnf.SelfSign {
    cnf.Organization = ""
    cnf.CommonName = ""
  }
  return cnf
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
    cnf.ListenTo = socket_address
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
    err := envconfig.Process("demarkate", cnf)
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
func Printf(format string, v ...interface{}) {
  log.Info(fmt.Sprintf(format, v...))
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
type SingleHostReverseProxyFunc func(*url.URL)(*httputil.ReverseProxy)

// H2c (cleartext http2) ReverseProxy
func NewSingleHostH2cReverseProxy(target *url.URL) (*httputil.ReverseProxy) {
  // We need to add the port of some common services since we force change
  // scheme to https further below
  if ! strings.Contains(target.Host, ":") {
    switch strings.ToLower(target.Scheme) {
      case "http":
        target.Host = target.Host + ":80"
      case "https":
        target.Host = target.Host + ":443"
      case "http-alt":
        target.Host = target.Host + ":8080"
      case "gopher":
        target.Host = target.Host + ":70"
    }
  }
  // Enforce https to use DialTLS transport for clear-text http2.
  target.Scheme = "https"
  // we ignore tls.Config in our custom dialer to always make clear-text connections
  dial := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
    return net.DialTimeout(network, addr, 3 * time.Second)
  }
  transport := &http2.Transport{
    // AllowHTTP true is not the same as bypassing DialTLS with a cleartext TCP
    // dialer (commented out)...
    // AllowHTTP: true,
    DialTLS: dial,
  }
  proxy := httputil.NewSingleHostReverseProxy(target)
  // Replace the transport with x/net/http2
  proxy.Transport = transport
  // Use our io.Writer log wrapper
  proxy.ErrorLog = logWrapper
  return proxy
}

// HTTP/2 (TLS) ReverseProxy
func NewSingleHostH2ReverseProxy(target *url.URL) (*httputil.ReverseProxy) {
  tlscc := &tls.Config{
    InsecureSkipVerify: true,
  }
  transport := &http2.Transport{
    TLSClientConfig: tlscc,
  }
  proxy := httputil.NewSingleHostReverseProxy(target)
  proxy.Transport = transport
  proxy.ErrorLog = logWrapper
  return proxy
}

// HTTP/1.1 and HTTP/2 ReverseProxy
func NewSingleHostHTTPReverseProxy(target *url.URL) (*httputil.ReverseProxy) {
  tlscc := &tls.Config{
    InsecureSkipVerify: true,
  }
  transport := &http.Transport{
    TLSClientConfig: tlscc,
  }
  proxy := httputil.NewSingleHostReverseProxy(target)
  proxy.Transport = transport
  proxy.ErrorLog = logWrapper
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
  DEMARKATE_LISTEN_TO     net.Listen address, e.g: ":8080"
  DEMARKATE_BACKEND       URL of backend endpoint, e.g: "http://mysvc:12345"
  DEMARKATE_BACKEND_TYPE  Choose single reverse proxy client type:
                          "h2c" (default), "http2", or "http" (for 2 and 1.1)
  DEMARKATE_CERT_FILES    Comma separated list of PEM, CRT or KEY files. It will
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
  var shrpf SingleHostReverseProxyFunc
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
  switch strings.ToLower(cnf.BackendType) {
    case "h2c", "http2c":
      shrpf = NewSingleHostH2cReverseProxy
    case "http2":
      shrpf = NewSingleHostH2ReverseProxy
    case "http", "http1":
      shrpf = NewSingleHostHTTPReverseProxy
    default:
      errors = append(errors, fmt.Errorf(`DEMARKATE_BACKEND_TYPE "%s" is unknown`, cnf.BackendType))
  }
  if cnf.ListenTo == "" {
    errors = append(errors, fmt.Errorf(`missing listen address, e.g: DEMARKATE_LISTEN_TO=":8080" %s`, os.Args[0]))
  }
  if cnf.Backend == "" {
    errors = append(errors, fmt.Errorf("missing backend URL, hint: environment variable DEMARKATE_BACKEND"))
  }
  backend_url, err := url.Parse(cnf.Backend)
  if err != nil {
    errors = append(errors, err)
  }
  if cnf.UsageOnSyntaxError && len(errors) > 0 {
    Usage()
    return fmt.Errorf("Syntax error")
  } else if len(errors) > 0 {
    for i, err := range errors {
      log.Error(err.Error())
      if i == len(errors) - 1 {
        // return the last err
        return err
      }
    }
  }

  startlog := log.WithFields(log.Fields{
      "DEMARKATE_PROTOCOL": cnf.Protocol,
      "DEMARKATE_LISTEN_TO": cnf.ListenTo,
      "DEMARKATE_BACKEND": cnf.Backend,
      "DEMARKATE_BACKEND_TYPE": cnf.BackendType,
      "DEMARKATE_CERT_FILES": cnf.CertFiles,
      "DEMARKATE_SELF_SIGN": cnf.SelfSign,
      "DEMARKATE_SELF_SIGN_ORG": cnf.Organization,
      "DEMARKATE_SELF_SIGN_CN": cnf.CommonName,
      "DEMARKATE_LOG": cnf.Log,
      "version": version,
  })
  startlog.Info("Initializing demarkate")

  proxy := shrpf(backend_url)

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

  handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    log.WithFields(log.Fields{
      "file": "access.log",
      "remote_addr": r.RemoteAddr,
      "method": r.Method,
      "request_uri": r.RequestURI,
      "proto": r.Proto,
      "content_length": r.ContentLength,
    }).Infof("%s DE %s", r.RequestURI, r.RemoteAddr)
    proxy.ServeHTTP(w, r)
  })

  srv := &http.Server{
    ReadTimeout: 30 * time.Second,
    WriteTimeout: 5 * time.Minute,
    IdleTimeout: 10 * time.Second,
    TLSConfig: tlsConfig,
    Handler: handler,
    ErrorLog: logWrapper,
  }

  log.Info(fmt.Sprintf("Starting demarkate %s proxy on address %s (%s) for backend %s", h2typeString, cnf.ListenTo, cnf.Protocol, cnf.Backend))

  lis, err := net.Listen(cnf.Protocol, cnf.ListenTo)
  if err != nil {
    log.Error(err.Error())
    return err
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

  // Start a HTTPS/HTTP2 server
  return srv.ServeTLS(lis, "" ,"")
}
