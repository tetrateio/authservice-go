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
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
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
	defaultNamespace = "default"
	clientSecretKey  = "client-secret"
)

var (
	_ run.PreRunner      = (*SecretController)(nil)
	_ run.ServiceContext = (*SecretController)(nil)
)

// SecretController watches secrets for updates and updates the configuration with the loaded data.
type SecretController struct {
	log           telemetry.Logger
	effectiveConf *configv1.Config
	originalConf  *configv1.Config
	secrets       sets.Set[string]
	restConf      *rest.Config
	k8sClient     client.Client
}

// NewSecretController creates a new k8s Controller that loads secrets from
// Kubernetes and updates the configuration with the loaded data.
func NewSecretController(cfg *configv1.Config) *SecretController {
	return &SecretController{
		log:           internal.Logger(internal.Config),
		effectiveConf: cfg,
	}
}

// PreRun saves the original configuration in PreRun phase because the
// configuration is loaded from the file in the Config Validate phase.
func (s *SecretController) PreRun() error {
	// Clone the configuration as we need to use the original client secret
	// configuration when reconciling the secret updates.
	s.originalConf = proto.Clone(s.effectiveConf).(*configv1.Config)

	// Collect the k8s secrets that are used in the configuration
	s.secrets = sets.New[string]()
	for _, c := range s.originalConf.Chains {
		for _, f := range c.Filters {
			oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
			if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
				continue
			}
			s.secrets.Insert(namespacedName(oidcCfg.Oidc.GetClientSecretRef()).String())
		}
	}

	// If there are no secrets to watch, we can skip starting the controller manager
	if s.secrets.Len() == 0 {
		return nil
	}

	var err error
	if s.restConf == nil {
		s.restConf, err = config.GetConfig()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLoadingConfig, err)
		}
	}

	return nil
}

func namespacedName(secretRef *oidcv1.OIDCConfig_SecretReference) types.NamespacedName {
	namespace := secretRef.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}
	return types.NamespacedName{
		Namespace: namespace,
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
	if s.secrets.Len() == 0 {
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

	// If the secret is not used in the configuration, we can ignore it
	if !s.secrets.Has(changedSecret) {
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

	for i, c := range s.originalConf.Chains {
		for j, f := range c.Filters {
			oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
			if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
				continue
			}
			namespace := oidcCfg.Oidc.GetClientSecretRef().Namespace
			if namespace == "" {
				namespace = defaultNamespace
			}
			clientSecret := namespacedName(oidcCfg.Oidc.GetClientSecretRef()).String()

			if clientSecret == changedSecret {
				s.log.Info("updating client-secret data from secret",
					"secret", clientSecret, "client-id", oidcCfg.Oidc.GetClientId())

				// Update the configuration with the loaded client secret
				s.effectiveConf.Chains[i].Filters[j].GetOidc().ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
					ClientSecret: string(clientSecretBytes),
				}
			}
		}
	}

	return ctrl.Result{}, nil
}
