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
	"fmt"

	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

var (
	_ run.ServiceContext = (*SecretController)(nil)
)

// SecretController watches secrets for updates and updates the configuration with the loaded data.
type SecretController struct {
	log       telemetry.Logger
	cfg       *configv1.Config
	oldCfg    *configv1.Config
	secrets   sets.Set[string]
	k8sClient client.Client
}

// NewSecretController creates a new k8s Controller that loads secrets from
// Kubernetes and updates the configuration with the loaded data.
func NewSecretController(cfg *configv1.Config) *SecretController {
	// Clone the configuration as we need to use the original client secret
	// configuration when reconciling the secret updates.
	oldCfg := proto.Clone(cfg).(*configv1.Config)

	// Collect the k8s secrets that are used in the configuration
	secrets := sets.New[string]()
	for _, c := range cfg.Chains {
		for _, f := range c.Filters {
			oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
			if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
				continue
			}
			namespace := oidcCfg.Oidc.GetClientSecretRef().Namespace
			if namespace == "" {
				namespace = defaultNamespace
			}
			secretName := types.NamespacedName{
				Namespace: namespace,
				Name:      oidcCfg.Oidc.GetClientSecretRef().GetName(),
			}.String()
			secrets.Insert(secretName)
		}
	}

	return &SecretController{
		log:     internal.Logger(internal.Config),
		cfg:     cfg,
		oldCfg:  oldCfg,
		secrets: secrets,
	}
}

// Name implements run.PreRunner
func (s *SecretController) Name() string { return "Secret controller" }

// ServeContext starts the controller manager and watches secrets for updates.
// The controller manager is encapsulated in the secret controller because we
// only need it to watch secrets and update the configuration.
func (s *SecretController) ServeContext(ctx context.Context) error {
	cfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLoadingConfig, err)
	}
	mgr, err := ctrl.NewManager(cfg, manager.Options{})
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
	if s.secrets.Has(changedSecret) {
		secret := new(corev1.Secret)
		if err := s.k8sClient.Get(ctx, req.NamespacedName, secret); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to get Secret: %w", err)
		}
		clientSecretBytes, ok := secret.Data[clientSecretKey]
		if !ok || len(clientSecretBytes) == 0 {
			return ctrl.Result{}, fmt.Errorf("%w: %s", ErrNoSecretData, changedSecret)
		}

		for i, c := range s.oldCfg.Chains {
			for j, f := range c.Filters {
				oidcCfg, ok := f.Type.(*configv1.Filter_Oidc)
				if !ok || oidcCfg.Oidc.GetClientSecretRef().GetName() == "" {
					continue
				}
				namespace := oidcCfg.Oidc.GetClientSecretRef().Namespace
				if namespace == "" {
					namespace = defaultNamespace
				}
				secretName := types.NamespacedName{
					Namespace: namespace,
					Name:      oidcCfg.Oidc.GetClientSecretRef().GetName(),
				}.String()
				if secretName == changedSecret {
					// Update the configuration with the loaded client secret
					s.cfg.Chains[i].Filters[j].GetOidc().ClientSecretConfig = &oidcv1.OIDCConfig_ClientSecret{
						ClientSecret: string(clientSecretBytes),
					}
				}

			}
		}
	}

	return ctrl.Result{}, nil
}
