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

package pemloader
import (
  "crypto"
  "crypto/ecdsa"
  "crypto/ed25519"
  "crypto/rsa"
  "crypto/elliptic"
  "crypto/tls"
  "crypto/x509"
  "crypto/x509/pkix"
  "crypto/rand"
  "encoding/pem"
  "io/ioutil"
  "math/big"
  "fmt"
  "time"
  "strings"
)


func FromSingleFile(path string) (*tls.Certificate, error) {
  var certificate tls.Certificate
  content, err := ioutil.ReadFile(path)
  if err != nil {
    return nil, err
  }

  for {
    block, remainder := pem.Decode(content)
    if block == nil {
      break
    }
    if block.Type == "CERTIFICATE" {
      certificate.Certificate = append(certificate.Certificate, block.Bytes)
    } else {
      certificate.PrivateKey, err = getPrivateKey(block.Bytes)
      if err != nil {
        return nil, fmt.Errorf("Unable to get private key from %s: %s", path, err)
      }
    }
    content = remainder
  }

  if len (certificate.Certificate) < 1 {
    return nil, fmt.Errorf("No certificate found in %s", path)
  } else if certificate.PrivateKey == nil {
    return nil, fmt.Errorf("No private key found in %s", path)
  }
  return &certificate, nil
}


func FromMultipleFiles(paths []string) (*tls.Certificate, error) {
  var certificate tls.Certificate
  for _, path := range paths {
    content, err := ioutil.ReadFile(path)
    if err != nil {
      return nil, err
    }
    for {
      block, remainder := pem.Decode(content)
      if block == nil {
        break
      }
      if block.Type == "CERTIFICATE" {
        certificate.Certificate = append(certificate.Certificate, block.Bytes)
      } else {
        certificate.PrivateKey, err = getPrivateKey(block.Bytes)
        if err != nil {
          return nil, fmt.Errorf("Unable to get private key from %s: %s", path)
        }
      }
      content = remainder
    }
  }
  if len (certificate.Certificate) < 1 {
    return nil, fmt.Errorf("No certificate found in %s", strings.Join(paths, ","))
  } else if certificate.PrivateKey == nil {
    return nil, fmt.Errorf("No private key found in %s", strings.Join(paths, ","))
  }
  return &certificate, nil
}



func GenerateSelfSignedCert(organization string, commonName string) (*tls.Certificate, error) {
  privatekey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
  if err != nil {
    return nil, err
  }
  template := x509.Certificate{ SerialNumber: big.NewInt(1),
                                Subject: pkix.Name{
                                  Organization: []string{organization},
                                  CommonName: commonName,
                                },
                                NotBefore: time.Now(),
                                NotAfter: time.Now().Add(time.Hour * 24 * 360),
                                KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
                                ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
                                BasicConstraintsValid: true,
                              }
  derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privatekey), privatekey)
  if err != nil {
    return nil, err
  }
  tlsCert := tls.Certificate{ Certificate: [][]byte{derBytes}, PrivateKey: privatekey }
  return &tlsCert, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func getPrivateKey(der []byte) (crypto.PrivateKey, error) {
  var key crypto.PrivateKey
  var err error
  key, err = x509.ParsePKCS1PrivateKey(der)
  if err == nil {
    return key, nil
  }
  key, err = x509.ParsePKCS8PrivateKey(der)
  if err == nil {
    switch key := key.(type) {
      case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
        return key, nil
      default:
        return nil, fmt.Errorf("Unknown private key type in PKCS#8")
    }
  }
  key, err = x509.ParseECPrivateKey(der)
  if err == nil {
    return key, nil
  }
  return nil, fmt.Errorf("Unable to obtain a private key")
}
