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

package main

import (
	"fmt"
	"os"

	"github.com/tetratelabs/log"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/run/pkg/signal"
	"github.com/tetratelabs/telemetry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/oidc"
	"github.com/tetrateio/authservice-go/internal/server"
)

func main() {
	k8sClient, err := getKubeClient()
	if err != nil {
		fmt.Printf("error creting k8s client: %v\n", err)
		os.Exit(-1)
	}

	var (
		configFile  = &internal.LocalConfigFile{}
		logging     = internal.NewLogSystem(log.New(), &configFile.Config)
		jwks        = oidc.NewJWKSProvider()
		sessions    = oidc.NewSessionStoreFactory(&configFile.Config)
		envoyAuthz  = server.NewExtAuthZFilter(&configFile.Config, jwks, sessions)
		authzServer = server.New(&configFile.Config, envoyAuthz.Register)
		healthz     = server.NewHealthServer(&configFile.Config)
		secrets     = internal.NewSecretLoader(&configFile.Config, k8sClient)
	)

	configLog := run.NewPreRunner("config-log", func() error {
		cfgLog := internal.Logger(internal.Config)
		if cfgLog.Level() == telemetry.LevelDebug {
			cfgLog.Debug("configuration loaded", "config", internal.ConfigToJSONString(&configFile.Config))
		}
		return nil
	})

	g := run.Group{Logger: internal.Logger(internal.Default)}

	g.Register(
		configFile,        // load the configuration
		logging,           // set up the logging system
		secrets,           // load the secrets and update the configuration
		configLog,         // log the configuration
		jwks,              // start the JWKS provider
		sessions,          // start the session store
		authzServer,       // start the server
		healthz,           // start the health server
		&signal.Handler{}, // handle graceful termination
	)

	if err := g.Run(); err != nil {
		fmt.Printf("Unexpected exit: %v\n", err)
		os.Exit(-1)
	}
}

// getKubeClient returns a new Kubernetes client used to load secrets.
func getKubeClient() (client.Client, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("error getting kube config: %w", err)
	}

	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("errot creating kube client: %w", err)
	}

	return cl, nil
}
