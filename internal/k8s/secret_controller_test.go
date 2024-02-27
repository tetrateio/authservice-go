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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/log"
)

const (
	defaultWait = time.Second * 100
	defaultTick = time.Millisecond * 20
)

func TestOIDCProcessWithKubernetesSecret(t *testing.T) {
	tests := []struct {
		name         string
		testFile     string
		hasSecretRef bool
	}{
		{"multiple secret refs", "oidc-with-multiple-secret-refs", true},
		{"no secret ref", "oidc-without-secret-ref", false},
		{"secret ref without data", "oidc-with-secret-ref-without-data", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// load test data
			originalConf := loadTestConf(t, fmt.Sprintf("testdata/%s-in.json", tt.testFile))
			expectedConf := loadTestConf(t, fmt.Sprintf("testdata/%s-out.json", tt.testFile))

			// start kube test env
			conf := startEnv(t)

			// start secret controller
			controller := NewSecretController(originalConf)
			controller.restConf = conf
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				err := controller.PreRun()
				require.NoError(t, err)
				err = controller.ServeContext(ctx)
				require.NoError(t, err)
			}()

			t.Cleanup(cancel)

			var secrets []*corev1.Secret
			if tt.hasSecretRef {
				// create test secrets
				secrets = createSecretsForTest(ctx, t, controller)
			}

			// if the original configuration is already the same as the expected
			// configuration, we need to call reconcile manually to make sure the
			// reconciliation happens before the assertion.
			if proto.Equal(originalConf, expectedConf) {
				for _, secret := range secrets {
					_, _ = controller.Reconcile(ctx, ctrl.Request{
						NamespacedName: types.NamespacedName{
							Namespace: secret.Namespace,
							Name:      secret.Name,
						},
					})
				}
			}

			// wait for the secret controller to update the configuration
			require.Eventually(t, func() bool {
				return proto.Equal(originalConf, expectedConf)
			}, defaultWait, defaultTick)
		})
	}
}

func startEnv(t *testing.T) *rest.Config {
	ctrl.SetLogger(log.NewLogrAdapter(internal.Logger(internal.K8s)))
	env := &envtest.Environment{}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		err := env.Stop()
		require.NoError(t, err)
	})
	return cfg
}

func createSecretsForTest(ctx context.Context, t *testing.T, controller *SecretController) []*corev1.Secret {
	// wait for k8s client to be ready
	require.Eventually(t, func() bool {
		return controller.k8sClient != nil
	}, defaultWait, defaultTick)

	secrets := []*corev1.Secret{
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "test-secret-1",
			},
			Data: map[string][]byte{
				clientSecretKey: []byte("fake-client-secret-1"),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "test-secret-2",
			},
			Data: map[string][]byte{
				clientSecretKey: []byte("fake-client-secret-2"),
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      "test-secret-without-data",
			},
		},
	}

	for _, secret := range secrets {
		require.NoError(t, controller.k8sClient.Create(ctx, secret))
	}
	return secrets
}

func loadTestConf(t *testing.T, file string) *configv1.Config {
	var conf = &configv1.Config{}
	content, err := os.ReadFile(file)
	require.NoError(t, err)
	err = protojson.Unmarshal(content, conf)
	require.NoError(t, err)
	return conf
}
