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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/k8s"
)

const (
	interval        = 100 * time.Millisecond
	intervalAndHalf = interval + interval/2
)

var (
	filterWithNoSecretRef = &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{},
		},
	}
)

func TestClientSecretLoader(t *testing.T) {
	tmpDir := t.TempDir()
	validFile := tmpDir + "/secret-file"
	require.NoError(t, os.WriteFile(validFile, []byte("file-data"), 0644))

	t.Setenv("env-var", "env-var-data")
	t.Setenv("env-var-empty", "")

	var (
		validSecretName   = "valid-secret"
		invalidSecretName = "invalid-secret"

		validSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: validSecretName},
			Data:       map[string][]byte{"client-secret": []byte("secret-data")},
		}
		invalidSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: invalidSecretName},
			Data:       map[string][]byte{"no-valid-key": []byte("unread")},
		}
	)

	kubeClient := fake.NewClientBuilder().WithObjects(validSecret, invalidSecret).Build()

	tests := []struct {
		name       string
		config     *configv1.Config
		wantConfig *configv1.Config
		wantErr    error
	}{
		{"no-config", nil, nil, nil},
		{"empty-config", &configv1.Config{}, &configv1.Config{}, nil},
		{
			"empty-filters",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithNoSecretRef}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithNoSecretRef}}}},
			nil,
		},
		{
			"client-secret-file",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretFile(validFile)}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretString("file-data")}}}},
			nil,
		},
		{
			"client-secret-ref",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretRef(validSecretName, "")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretString("secret-data")}}}},
			nil,
		},
		{
			"client-secret-env-var",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretEnvVar("env-var")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretString("env-var-data")}}}},
			nil,
		},
		{
			"client-string",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretString("string-data")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretString("string-data")}}}},
			nil,
		},
		{
			"client-secret-ref-not-found",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretRef("non-existent", "")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretRef("non-existent", "")}}}},
			k8s.ErrGetSecret,
		},
		{
			"client-secret-ref-invalid",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretRef(invalidSecretName, "")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretRef(invalidSecretName, "")}}}},
			k8s.ErrNoSecretData,
		},
		{
			"client-file-not-found",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretFile("non-existent")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretFile("non-existent")}}}},
			os.ErrNotExist,
		},
		{
			"client-env-var-not-found",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretEnvVar("non-existent")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretEnvVar("non-existent")}}}},
			internal.ErrEmptyOrNotFound,
		},
		{
			"client-env-var-empty",
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretEnvVar("env-var-empty")}}}},
			&configv1.Config{Chains: []*configv1.FilterChain{{Filters: []*configv1.Filter{filterWithClientSecretEnvVar("env-var-empty")}}}},
			internal.ErrEmptyOrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			cl := NewClientSecretLoader(ctx, tt.config, mockClientLoader{Client: kubeClient})
			err := cl.PreRun()
			require.ErrorIs(t, err, tt.wantErr)
			require.True(t, proto.Equal(tt.wantConfig, tt.config))
		})
	}
}

func TestClientLoaderUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	validFile := tmpDir + "/secret-file"
	require.NoError(t, os.WriteFile(validFile, []byte("file-data"), 0644))

	var (
		validEnvVar   = "env-var"
		invalidEnvVar = "invalid-env-var"
	)

	t.Setenv(validEnvVar, "env-var-data")
	t.Setenv(invalidEnvVar, "")

	var (
		validSecretName   = "valid-secret"
		invalidSecretName = "invalid-secret"

		validSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: validSecretName},
			Data:       map[string][]byte{"client-secret": []byte("secret-data")},
		}
		invalidSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: invalidSecretName},
			Data:       map[string][]byte{"no-valid-key": []byte("unread")},
		}

		config = &configv1.Config{
			Chains: []*configv1.FilterChain{{
				Filters: []*configv1.Filter{
					filterWithClientSecretRef(validSecretName, ""),
					filterWithClientSecretFile(validFile),
					filterWithClientSecretEnvVar(validEnvVar)},
			}},
		}
	)

	kubeClient := fake.NewClientBuilder().WithObjects(validSecret, invalidSecret).Build()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// initial load should not fail
	cl := NewClientSecretLoader(ctx, config, mockClientLoader{Client: kubeClient})
	require.NoError(t, cl.PreRun())

	// verify config is updated with content
	require.Equal(t, "secret-data", config.Chains[0].Filters[0].GetOidc().GetClientSecret())
	require.Equal(t, "file-data", config.Chains[0].Filters[1].GetOidc().GetClientSecret())
	require.Equal(t, "env-var-data", config.Chains[0].Filters[2].GetOidc().GetClientSecret())

	// update secret content
	validSecret.Data["client-secret"] = []byte("updated-secret-data")
	require.NoError(t, kubeClient.Update(ctx, validSecret))
	time.Sleep(intervalAndHalf)

	// verify config is updated with new content only for the one with secret ref
	require.Equal(t, "updated-secret-data", config.Chains[0].Filters[0].GetOidc().GetClientSecret())
	require.Equal(t, "file-data", config.Chains[0].Filters[1].GetOidc().GetClientSecret())
	require.Equal(t, "env-var-data", config.Chains[0].Filters[2].GetOidc().GetClientSecret())

	// update file content
	require.NoError(t, os.WriteFile(validFile, []byte("updated-file-data"), 0644))
	time.Sleep(intervalAndHalf)

	// verify config is updated with new content only for the one with secret file
	require.Equal(t, "updated-secret-data", config.Chains[0].Filters[0].GetOidc().GetClientSecret())
	require.Equal(t, "updated-file-data", config.Chains[0].Filters[1].GetOidc().GetClientSecret())
	require.Equal(t, "env-var-data", config.Chains[0].Filters[2].GetOidc().GetClientSecret())

	// update env var content
	t.Setenv(validEnvVar, "updated-env-var-data")
	time.Sleep(intervalAndHalf)

	// verify config is updated with new content only for the one with secret env var
	require.Equal(t, "updated-secret-data", config.Chains[0].Filters[0].GetOidc().GetClientSecret())
	require.Equal(t, "updated-file-data", config.Chains[0].Filters[1].GetOidc().GetClientSecret())
	require.Equal(t, "updated-env-var-data", config.Chains[0].Filters[2].GetOidc().GetClientSecret())

	// update secret, file and env var to empty content
	validSecret.Data["client-secret"] = []byte("")
	require.NoError(t, kubeClient.Update(ctx, validSecret))
	require.NoError(t, os.WriteFile(validFile, []byte(""), 0644))
	t.Setenv(validEnvVar, "")
	time.Sleep(intervalAndHalf)

	// verify config is not modified
	require.Equal(t, "updated-secret-data", config.Chains[0].Filters[0].GetOidc().GetClientSecret())
	require.Equal(t, "updated-file-data", config.Chains[0].Filters[1].GetOidc().GetClientSecret())
	require.Equal(t, "updated-env-var-data", config.Chains[0].Filters[2].GetOidc().GetClientSecret())

	// update secret to use an invalid key
	validSecret.Data = map[string][]byte{"invalid-key": []byte("invalid-secret-data")}
	require.NoError(t, kubeClient.Update(ctx, validSecret))
	time.Sleep(intervalAndHalf)

	// verify config is not modified
	require.Equal(t, "updated-secret-data", config.Chains[0].Filters[0].GetOidc().GetClientSecret())
	require.Equal(t, "updated-file-data", config.Chains[0].Filters[1].GetOidc().GetClientSecret())
	require.Equal(t, "updated-env-var-data", config.Chains[0].Filters[2].GetOidc().GetClientSecret())
}

func TestClientSecretLoaderName(t *testing.T) {
	cl := NewClientSecretLoader(context.Background(), &configv1.Config{}, mockClientLoader{})
	require.Equal(t, "Secret loader", cl.Name())
}

func filterWithClientSecretRef(name, namespace string) *configv1.Filter {
	return &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{
				ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecretRef{
					ClientSecretRef: &oidcv1.OIDCConfig_SecretReference{
						Name: name, Namespace: namespace,
					},
				},
				ClientSecretRefreshInterval: durationpb.New(interval),
			},
		},
	}
}

func filterWithClientSecretFile(file string) *configv1.Filter {
	return &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{
				ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecretFile{
					ClientSecretFile: file,
				},
				ClientSecretRefreshInterval: durationpb.New(interval),
			},
		},
	}
}

func filterWithClientSecretEnvVar(envVar string) *configv1.Filter {
	return &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{
				ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecretEnvVar{
					ClientSecretEnvVar: envVar,
				},
				ClientSecretRefreshInterval: durationpb.New(interval),
			},
		},
	}
}

func filterWithClientSecretString(secret string) *configv1.Filter {
	return &configv1.Filter{
		Type: &configv1.Filter_Oidc{
			Oidc: &oidcv1.OIDCConfig{
				ClientSecretConfig: &oidcv1.OIDCConfig_ClientSecret{
					ClientSecret: secret,
				},
				// when config is updated, refresh interval is not removed
				ClientSecretRefreshInterval: durationpb.New(interval),
			},
		},
	}
}

var _ k8s.ClientLoader = mockClientLoader{}

type mockClientLoader struct {
	client.Client
}

func (m mockClientLoader) Name() string       { return "mockClientLoader" }
func (m mockClientLoader) Get() client.Client { return m.Client }
