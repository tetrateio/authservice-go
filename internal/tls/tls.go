// Copyright 2024 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/tetratelabs/telemetry"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/k8s"
)

const caSecretkey = "ca.crt"

type (
	// Config is an interface for the TLS configuration of the AuthService.
	Config interface {
		// GetTrustedCertificateAuthority returns the trusted certificate authority PEM.
		GetTrustedCertificateAuthority() string
		// GetTrustedCertificateAuthorityFile returns the path to the trusted certificate authority file.
		GetTrustedCertificateAuthorityFile() string
		// GetTrustedCertificateAuthoritySecret returns the secret containing the trusted certificate authority.
		GetTrustedCertificateAuthoritySecret() *oidcv1.OIDCConfig_SecretReference
		// GetSkipVerifyPeerCert returns whether to skip verification of the peer certificate.
		GetSkipVerifyPeerCert() *structpb.Value
		// GetTrustedCertificateAuthorityRefreshInterval returns interval at which the trusted certificate
		// authority should be refreshed.
		GetTrustedCertificateAuthorityRefreshInterval() *durationpb.Duration
	}

	// ConfigPool is an interface for a pool of TLS configurations.
	ConfigPool interface {
		// LoadTLSConfig loads a TLS configuration from the given Config.
		LoadTLSConfig(config Config) (*tls.Config, error)
	}

	// tlsConfigPool is a pool of TLS configurations.
	// That reloads the trusted certificate authority when there are changes.
	tlsConfigPool struct {
		log telemetry.Logger

		mu        sync.RWMutex
		configs   map[string]*tls.Config
		caWatcher *internal.FileWatcher
		k8sLoader k8s.ClientLoader
	}
)

// NewTLSConfigPool creates a new ConfigPool.
func NewTLSConfigPool(ctx context.Context, k8sLoader k8s.ClientLoader) ConfigPool {
	return &tlsConfigPool{
		log:       internal.Logger(internal.Config),
		configs:   make(map[string]*tls.Config),
		caWatcher: internal.NewFileWatcher(ctx),
		k8sLoader: k8sLoader,
	}
}

// LoadTLSConfig loads a TLS configuration from the given Config.
func (p *tlsConfigPool) LoadTLSConfig(config Config) (*tls.Config, error) {
	encConfig := encodeConfig(config)
	id := encConfig.hash()
	if tlsConfig, ok := p.configs[id]; ok {
		return tlsConfig, nil
	}

	log := p.log.With("id", id)
	log.Info("loading new TLS config", "config", encConfig.JSON())
	tlsConfig := &tls.Config{}

	// Load the trusted CA PEM from the config
	var ca []byte
	switch {
	case config.GetTrustedCertificateAuthority() != "":
		ca = []byte(config.GetTrustedCertificateAuthority())

	case config.GetTrustedCertificateAuthorityFile() != "":
		var err error
		ca, err = p.caWatcher.WatchFile(
			internal.NewFileReader(config.GetTrustedCertificateAuthorityFile()),
			config.GetTrustedCertificateAuthorityRefreshInterval().AsDuration(),
			func(data []byte) { p.updateCA(id, data) },
		)
		if err != nil {
			return nil, fmt.Errorf("error loading trusted CA file: %w", err)
		}

	case config.GetTrustedCertificateAuthoritySecret() != nil:
		secretReader := k8s.NewSecretReader(p.k8sLoader.Get(),
			config.GetTrustedCertificateAuthoritySecret().GetName(),
			config.GetTrustedCertificateAuthoritySecret().GetNamespace(),
			caSecretkey,
		)
		var err error
		ca, err = p.caWatcher.WatchFile(
			secretReader,
			config.GetTrustedCertificateAuthorityRefreshInterval().AsDuration(),
			func(data []byte) { p.updateCA(id, data) },
		)
		if err != nil {
			return nil, fmt.Errorf("error loading trusted CA secret: %w", err)
		}

	case config.GetSkipVerifyPeerCert() != nil:
		tlsConfig.InsecureSkipVerify = internal.BoolStrValue(config.GetSkipVerifyPeerCert())

	default:
		// No CA or skip verification, return nil TLS config
		return nil, nil
	}

	// Add the loaded CA to the TLS config
	if len(ca) != 0 {
		if internal.BoolStrValue(config.GetSkipVerifyPeerCert()) {
			log.Info("`skip_verify_peer_cert` is set to true but there's also a trusted certificate authority, ignoring `skip_verify_peer_cert`")
		}

		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error creating system cert pool: %w", err)
		}

		if ok := certPool.AppendCertsFromPEM(ca); !ok {
			return nil, errors.New("could no load trusted certificate authority")
		}

		tlsConfig.RootCAs = certPool
	}

	// Save the TLS config to the pool
	p.mu.Lock()
	p.configs[id] = tlsConfig
	p.mu.Unlock()
	return tlsConfig, nil
}

func (p *tlsConfigPool) updateCA(id string, caPem []byte) {
	log := p.log.With("id", id)

	// Load the TLS config
	p.mu.Lock()
	tlsConfig, ok := p.configs[id]
	if !ok {
		log.Error("couldn't update TLS config", errors.New("config not found"))
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	// Add the loaded CA to the TLS config
	certPool, err := x509.SystemCertPool()
	if err != nil {
		log.Error("error creating system cert pool", err)
		return
	}

	if ok := certPool.AppendCertsFromPEM(caPem); !ok {
		log.Error("could not load trusted certificate authority", errors.New("failed to append certificate in the cert pool"))
		return
	}

	// Update the TLS config
	tlsConfig.RootCAs = certPool
	log.Info("updated TLS config with new trusted certificate authority")

	p.mu.Lock()
	p.configs[id] = tlsConfig
	p.mu.Unlock()
}

// tlsConfigEncoder is the internal representation of a Config.
// It handles some useful methods for the Config.
type tlsConfigEncoder struct {
	SkipVerifyPeerCert       bool   `json:"skipVerifyPeerCert,omitempty"`
	TrustedCA                string `json:"trustedCertificateAuthority,omitempty"`
	TrustedCAFile            string `json:"trustedCertificateAuthorityFile,omitempty"`
	TrustedCASecret          string `json:"trustedCertificateAuthoritySecret,omitempty"`
	TrustedCARefreshInterval string `json:"trustedCertificateAuthorityRefreshInterval,omitempty"`
}

// encodeConfig converts a Config to an tlsConfigEncoder.
func encodeConfig(config Config) tlsConfigEncoder {
	return tlsConfigEncoder{
		TrustedCA:                config.GetTrustedCertificateAuthority(),
		TrustedCAFile:            config.GetTrustedCertificateAuthorityFile(),
		TrustedCASecret:          caSecretToString(config.GetTrustedCertificateAuthoritySecret()),
		TrustedCARefreshInterval: config.GetTrustedCertificateAuthorityRefreshInterval().AsDuration().String(),
		SkipVerifyPeerCert:       internal.BoolStrValue(config.GetSkipVerifyPeerCert()),
	}
}

// hash returns the hash of the tls config.
func (c tlsConfigEncoder) hash() string {
	buff := bytes.Buffer{}
	_, _ = buff.WriteString(fmt.Sprintf("%t", c.SkipVerifyPeerCert))
	_, _ = buff.WriteString(c.TrustedCA)
	_, _ = buff.WriteString(c.TrustedCAFile)
	_, _ = buff.WriteString(c.TrustedCASecret)
	_, _ = buff.WriteString(c.TrustedCARefreshInterval)
	hash := fnv.New64a()
	_, _ = hash.Write(buff.Bytes())
	out := hash.Sum(make([]byte, 0, 15))
	return hex.EncodeToString(out)
}

// JSON returns the JSON representation of the tls config.
func (c tlsConfigEncoder) JSON() string {
	jsonBytes, _ := json.Marshal(c)
	return string(jsonBytes)
}

func caSecretToString(secret *oidcv1.OIDCConfig_SecretReference) string {
	if secret == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s", secret.GetNamespace(), secret.GetName())
}
