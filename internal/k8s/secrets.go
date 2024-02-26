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

package k8s

import (
	"context"
	"errors"
	"fmt"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

const (
	defaultNamespace = "default"
	clientSecretKey  = "client-secret"
)

var (
	_ run.PreRunner = (*SecretLoader)(nil)

	ErrGetSecret    = errors.New("error getting secret")
	ErrNoSecretData = errors.New("client-secret not found in secret")
)

// SecretLoader is a pre-runner that loads secrets from Kubernetes and updates
// the configuration with the loaded data.
type SecretLoader struct {
	log             telemetry.Logger
	cfg             *configv1.Config
	k8sClientLoader ClientLoader
}

// NewSecretLoader creates a new that loads secrets from Kubernetes and updates
// // the configuration with the loaded data.
func NewSecretLoader(cfg *configv1.Config, loader ClientLoader) *SecretLoader {
	return &SecretLoader{
		log:             internal.Logger(internal.Config),
		cfg:             cfg,
		k8sClientLoader: loader,
	}
}

// Name implements run.PreRunner
func (s *SecretLoader) Name() string { return "Secret loader" }

// PreRun processes all the OIDC configurations and loads all required secrets from Kubernetes.
func (s *SecretLoader) PreRun() error {
	var (
		k8sClient = s.k8sClientLoader.Get()
		errs      []error
	)

	for _, c := range s.cfg.Chains {
		for _, f := range c.Filters {
			oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
			if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
				continue
			}

			var (
				name      = oidcCfg.Oidc.GetClientSecretRef().GetName()
				namespace = oidcCfg.Oidc.GetClientSecretRef().GetNamespace()
			)

			s.log.Info("loading client-secret from secret",
				"secret", fmt.Sprintf("%s/%s", name, namespace),
				"client-id", oidcCfg.Oidc.GetClientId())

			secretReader := NewSecretReader(k8sClient, name, namespace, clientSecretKey)
			clientSecret, err := secretReader.Read()
			if err != nil {
				errs = append(errs, fmt.Errorf("error reading secret %s/%s: %w", name, namespace, err))
				continue
			}

			// Update the configuration with the loaded client secret
			oidcCfg.Oidc.ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
				ClientSecret: string(clientSecret),
			}
		}
	}

	return errors.Join(errs...)
}

// SecretReader reads a secret from Kubernetes.
type SecretReader struct {
	log             telemetry.Logger
	name, namespace string
	key             string
	k8sClient       client.Client
}

// NewSecretReader creates a new SecretReader.
func NewSecretReader(k8sClient client.Client, name, namespace, key string) *SecretReader {
	if namespace == "" {
		namespace = defaultNamespace
	}
	return &SecretReader{
		log:       internal.Logger(internal.Config),
		name:      name,
		namespace: namespace,
		key:       key,
		k8sClient: k8sClient,
	}
}

// ID implements internal.Reader
func (s *SecretReader) ID() string {
	return fmt.Sprintf("k8s-secret-(%s/%s)", s.namespace, s.name)
}

// Read implements internal.Reader
func (s *SecretReader) Read() ([]byte, error) {
	secretName := types.NamespacedName{
		Namespace: s.namespace,
		Name:      s.name,
	}

	secret := &corev1.Secret{}
	if err := s.k8sClient.Get(context.Background(), secretName, secret); err != nil {
		s.log.Error("error getting secret", err, "secret", secretName.String())
		return nil, fmt.Errorf("%w: %w", ErrGetSecret, err)
	}

	data := secret.Data[s.key]
	if len(data) == 0 {
		s.log.Error("key not found in secret", ErrNoSecretData, "secret", secretName.String(), "key", s.key)
		return nil, fmt.Errorf("%w: %s", ErrNoSecretData, secretName.String())
	}
	return data, nil
}
