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
	"errors"
	"fmt"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	"github.com/tetrateio/authservice-go/internal"
)

var (
	ErrLoadingConfig  = errors.New("error loading kube config")
	ErrCreatingClient = errors.New("error creating kube client")
)

var (
	_ ClientLoader  = (*clientLoader)(nil)
	_ run.PreRunner = (*clientLoader)(nil)
)

type (
	// ClientLoader is an interface for a pre-runner that loads the Kubernetes client.
	ClientLoader interface {
		run.Unit
		Get() client.Client
	}

	clientLoader struct {
		log    telemetry.Logger
		config *configv1.Config
		client client.Client
	}
)

// NewClientLoader creates a new Kubernetes client loader.
// The client loader is a pre-runner that loads the Kubernetes client depending on the configuration.
// If there is no secret reference in the configuration, the client loader will not load the Kubernetes client.
func NewClientLoader(config *configv1.Config) ClientLoader {
	return &clientLoader{
		log:    internal.Logger(internal.Config),
		config: config,
	}
}

// Get returns the Kubernetes client if loaded, otherwise it returns nil.
// Is assumed the client will not be required if there's no config requiring k8s secrets.
func (c *clientLoader) Get() client.Client {
	if c.client == nil {
		c.log.Error("Kubernetes client not loaded", errors.New("no expected kubernetes config"))
	}
	return c.client
}

// Name implements run.Unit
func (c *clientLoader) Name() string {
	return "Kubernetes client loader"
}

// PreRun implements run.PreRunner
// It loads the Kubernetes client if there is any OIDC filter that requires it.
func (c *clientLoader) PreRun() error {
	if !mustLoadK8sClient(c.config) {
		return nil
	}

	c.log.Info("Loading Kubernetes client")
	var err error
	c.client, err = getKubeClient()
	return err
}

// mustLoadK8sClient returns true if the configuration requires the Kubernetes client to be loaded.
func mustLoadK8sClient(c *configv1.Config) bool {
	for _, chain := range c.Chains {
		for _, filter := range chain.Filters {
			if oidc, ok := filter.Type.(*configv1.Filter_Oidc); ok {
				if oidc.Oidc.GetClientSecretRef() != nil {
					return true
				}
				if oidc.Oidc.GetTrustedCertificateAuthoritySecret() != nil {
					return true
				}
			}
		}
	}
	return false
}

// getKubeClient returns a new Kubernetes client used to load secrets.
func getKubeClient() (client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadingConfig, err)
	}

	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreatingClient, err)
	}

	return cl, nil
}
