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
	"os"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

const (
	clientSecretKey = "client-secret"
)

var (
	_ run.PreRunner      = (*SecretController)(nil)
	_ run.ServiceContext = (*SecretController)(nil)
)

// SecretController watches secrets for updates and updates the configuration with the loaded data.
type SecretController struct {
	log       telemetry.Logger
	config    *configv1.Config
	secrets   map[string][]*oidcv1.OIDCConfig
	restConf  *rest.Config
	k8sClient client.Client
	namespace string
}

// NewSecretController creates a new k8s Controller that loads secrets from
// Kubernetes and updates the configuration with the loaded data.
func NewSecretController(cfg *configv1.Config) *SecretController {
	return &SecretController{
		log:    internal.Logger(internal.Config),
		config: cfg,
	}
}

// PreRun saves the original configuration in PreRun phase because the
// configuration is loaded from the file in the Config Validate phase.
func (s *SecretController) PreRun() error {
	var needWatchSecrets = false

	// Check if there are any k8s secrets to watch
	for _, c := range s.config.Chains {
		for _, f := range c.Filters {
			oidcCfg, isOIDCConf := f.Type.(*configv1.Filter_Oidc)
			if isOIDCConf && oidcCfg.Oidc.GetClientSecretRef() != nil {
				needWatchSecrets = true
				break
			}
		}
	}

	// If there are no secrets to watch, we can skip starting the controller manager
	if !needWatchSecrets {
		return nil
	}

	// Load the current namespace from the service account directory
	if s.namespace == "" {
		const namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
		data, err := os.ReadFile(namespaceFile)
		if err != nil {
			return fmt.Errorf("error reading namespace file %s: %w", namespaceFile, err)
		}
		s.namespace = string(data)
	}

	// Collect the k8s secrets that are used in the configuration
	s.secrets = make(map[string][]*oidcv1.OIDCConfig)
	for _, c := range s.config.Chains {
		for _, f := range c.Filters {
			oidcCfg, isOIDCConf := f.Type.(*configv1.Filter_Oidc)
			if !isOIDCConf ||
				oidcCfg.Oidc.GetClientSecretRef() == nil ||
				oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
				continue
			}

			ref := oidcCfg.Oidc.GetClientSecretRef()
			if ref.Namespace != "" && ref.Namespace != s.namespace {
				return fmt.Errorf(
					"cross-namespace secret reference is not allowed:"+
						" secret reference namespace %s does not match the current namespace %s",
					ref.Namespace, s.namespace)
			}

			key := secretNamespacedName(ref, s.namespace).String()
			s.secrets[key] = append(s.secrets[key], oidcCfg.Oidc)
		}
	}

	if s.restConf == nil {
		conf, err := config.GetConfig()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLoadingConfig, err)
		}
		s.restConf = conf
	}

	return nil
}

func secretNamespacedName(secretRef *oidcv1.OIDCConfig_SecretReference, currentNamespace string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: currentNamespace,
		Name:      secretRef.GetName(),
	}
}

// Name implements run.PreRunner
func (s *SecretController) Name() string { return "Secret controller" }

// ServeContext starts the controller manager and watches secrets for updates.
// The controller manager is encapsulated in the secret controller because we
// only need it to watch secrets and update the configuration.
func (s *SecretController) ServeContext(ctx context.Context) error {
	// If there are no secrets to watch, we can skip starting the controller manager
	if len(s.secrets) == 0 {
		<-ctx.Done()
		return nil
	}

	//TODO: Add manager options, like metrics, healthz, leader election, etc.
	mgr, err := ctrl.NewManager(s.restConf, manager.Options{})
	s.k8sClient = mgr.GetClient()
	if err != nil {
		return fmt.Errorf("error creating controller manager: %w", err)
	}

	if err = ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(s); err != nil {
		return fmt.Errorf("error creating secret controller:%w", err)
	}

	if err = mgr.Start(ctx); err != nil {
		return fmt.Errorf("error starting controller manager:%w", err)
	}

	return nil
}

func (s *SecretController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	changedSecret := req.NamespacedName.String()

	oidcConfigs, exist := s.secrets[changedSecret]

	// If the secret is not used in the configuration, we can ignore it
	if !exist {
		return ctrl.Result{}, nil
	}

	secret := new(corev1.Secret)
	if err := s.k8sClient.Get(ctx, req.NamespacedName, secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !secret.DeletionTimestamp.IsZero() {
		// Secret is being deleted, ignore it
		return ctrl.Result{}, nil
	}

	clientSecretBytes, ok := secret.Data[clientSecretKey]
	if !ok || len(clientSecretBytes) == 0 {
		s.log.Error("", errors.New("client-secret not found in secret"), "secret", secret)
		// Do not return an error here, as trying to process the secret again
		// will not help when the data is not present.
		return ctrl.Result{}, nil
	}

	for _, oidcConfig := range oidcConfigs {
		s.log.Info("updating client-secret data from secret",
			"secret", secret, "client-id", oidcConfig.GetClientId())

		// Update the configuration with the loaded client secret
		oidcConfig.ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
			ClientSecret: string(clientSecretBytes),
		}
	}

	return ctrl.Result{}, nil
}
