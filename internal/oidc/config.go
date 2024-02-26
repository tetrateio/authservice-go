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

package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/k8s"
)

const clientSecretKey = "client-secret"

var _ run.PreRunner = (*ClientSecretLoader)(nil)

// ClientSecretLoader is a pre-runner that loads secrets from Kubernetes and updates
// the configuration with the loaded data.
type ClientSecretLoader struct {
	log             telemetry.Logger
	cfg             *configv1.Config
	ctx             context.Context
	k8sClientLoader k8s.ClientLoader
}

// NewClientSecretLoader creates a new service that loads client secrets and updates
// the configuration with the loaded data.
func NewClientSecretLoader(ctx context.Context, cfg *configv1.Config, loader k8s.ClientLoader) *ClientSecretLoader {
	return &ClientSecretLoader{
		log:             internal.Logger(internal.Config),
		ctx:             ctx,
		cfg:             cfg,
		k8sClientLoader: loader,
	}
}

// Name implements run.PreRunner
func (s *ClientSecretLoader) Name() string { return "Secret loader" }

// PreRun processes all the OIDC configurations and loads all required secrets from Kubernetes.
func (s *ClientSecretLoader) PreRun() error {
	var (
		k8sClient = s.k8sClientLoader.Get()
		errs      []error
		watcher   *internal.FileWatcher
	)

	for _, c := range s.cfg.GetChains() {
		for _, f := range c.GetFilters() {
			oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
			if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" && oidcCfg.Oidc.GetClientSecretFile() == "" {
				continue
			}

			if watcher == nil {
				watcher = internal.NewFileWatcher(s.ctx)
			}

			var (
				clientSecret []byte
				err          error
				clientID     = oidcCfg.Oidc.GetClientId()
			)

			switch {

			case oidcCfg.Oidc.GetClientSecretFile() != "":
				file := oidcCfg.Oidc.GetClientSecretFile()
				clientSecret, err = watcher.WatchFile(internal.NewFileReader(file),
					oidcCfg.Oidc.GetClientSecretRefreshInterval().AsDuration(),
					func(data []byte) {
						// Update the configuration with the loaded client secret
						log := s.log.With("file", file, "client-id", clientID)
						updateClientSecret(log, data, oidcCfg.Oidc)
					})
				if err != nil {
					errs = append(errs, fmt.Errorf("error reading file %s: %w", file, err))
				}

			case oidcCfg.Oidc.GetClientSecretRef() != nil:
				var (
					name      = oidcCfg.Oidc.GetClientSecretRef().GetName()
					namespace = oidcCfg.Oidc.GetClientSecretRef().GetNamespace()
				)
				secretReader := k8s.NewSecretReader(k8sClient, name, namespace, clientSecretKey)
				clientSecret, err = watcher.WatchFile(secretReader, oidcCfg.Oidc.GetClientSecretRefreshInterval().AsDuration(),
					func(data []byte) {
						// Update the configuration with the loaded client secret
						log := s.log.With("secret", fmt.Sprintf("%s/%s", name, namespace), "client-id", clientID)
						updateClientSecret(log, data, oidcCfg.Oidc)
					})
				if err != nil {
					errs = append(errs, fmt.Errorf("error reading secret %s/%s: %w", name, namespace, err))
				}
			}

			if err != nil {
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

func updateClientSecret(log telemetry.Logger, clientSecret []byte, oidcCfg *oidcv1.OIDCConfig) {
	if len(clientSecret) == 0 {
		log.Error("aborting client-secret update", errors.New("data is empty"))
		return
	}
	log.Info("updating client-secret in configuration")
	// Update the configuration with the loaded client secret
	oidcCfg.ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
		ClientSecret: string(clientSecret),
	}
}
