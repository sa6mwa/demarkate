package main
import (
  "os"
  "github.com/sa6mwa/demarkate"
)
func main() {
  config := demarkate.New(demarkate.UsageOnSyntaxError(true), demarkate.EnvConfig())
  err := demarkate.Start(&config)
  if err == nil {
    demarkate.Errorf("QRT UNKNOWN REASON")
  }
  // demarkate has already logged the error, so we don't need to do it twice
  os.Exit(1)
}
