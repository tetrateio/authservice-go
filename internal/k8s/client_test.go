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
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

var (
	filterWithClientSecretRef = &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{
				ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecretRef{
					ClientSecretRef: &oidcv1.OIDCConfig_SecretReference{
						Name: "client-secret",
					},
				},
			},
		},
	}
	filterWithTrustedCASecretRef = &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{
				TrustedCaConfig: &oidcv1.OIDCConfig_TrustedCertificateAuthoritySecret{
					TrustedCertificateAuthoritySecret: &oidcv1.OIDCConfig_SecretReference{
						Name: "trusted-ca",
					},
				},
			},
		},
	}
	filterWithNoSecretRef = &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{},
		},
	}
)

func TestClientLoader(t *testing.T) {

	tests := []struct {
		name       string
		config     *configv1.Config
		kubeconfig string
		wantErr    error
		wantClient bool
	}{
		{"no-secret-ref-no-kubeconfig", &configv1.Config{}, "", nil, false},
		{
			"no-secret-ref-valid-kubeconfig", &configv1.Config{
				Chains: []*configv1.FilterChain{{
					Filters: []*configv1.Filter{filterWithNoSecretRef},
				}},
			},
			"testdata/kubeconfig",
			nil,
			false},
		{
			"client-secret-ref-valid-kubeconfig",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{
					Filters: []*configv1.Filter{filterWithClientSecretRef},
				}},
			},
			"testdata/kubeconfig",
			nil,
			true,
		},
		{
			"trusted-ca-secret-ref-valid-kubeconfig",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{
					Filters: []*configv1.Filter{filterWithTrustedCASecretRef},
				}},
			},
			"testdata/kubeconfig",
			nil,
			true,
		},
		{
			"secret-ref-but-no-kubeconfig",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{
					Filters: []*configv1.Filter{filterWithClientSecretRef, filterWithTrustedCASecretRef},
				}},
			},
			"",
			ErrLoadingConfig,
			false,
		},
		{
			"secret-ref-but-invalid-kubeconfig",
			&configv1.Config{
				Chains: []*configv1.FilterChain{{
					Filters: []*configv1.Filter{filterWithClientSecretRef, filterWithTrustedCASecretRef},
				}},
			},
			"testdata/kubeconfig-invalid",
			ErrCreatingClient,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KUBECONFIG", tt.kubeconfig)

			cl := NewClientLoader(tt.config)
			err := cl.(run.PreRunner).PreRun()

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.wantClient {
				require.NotNil(t, cl.Get())
			} else {
				require.Nil(t, cl.Get())
			}
		})
	}
}
