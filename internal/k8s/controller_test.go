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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/log"
)

const (
	defaultWait = time.Second * 10
	defaultTick = time.Millisecond * 20
)

func TestOIDCProcessWithKubernetesSecret(t *testing.T) {
	// start kube test env
	testEnv, conf := startEnv(t)

	// load test data
	var originalConf = &configv1.Config{}
	content, err := os.ReadFile("testdata/oidc-with-multiple-secret-ref-in.json")
	require.NoError(t, err)
	err = protojson.Unmarshal(content, originalConf)
	require.NoError(t, err)

	var effectiveConf = &configv1.Config{}
	content, err = os.ReadFile("testdata/oidc-with-multiple-secret-ref-out.json")
	require.NoError(t, err)
	err = protojson.Unmarshal(content, effectiveConf)
	require.NoError(t, err)

	// start secret controller
	controller := NewSecretController(originalConf)
	controller.restConf = conf
	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	go func() {
		err = controller.PreRun()
		require.NoError(t, err)
		err = controller.ServeContext(ctx)
		require.NoError(t, err)
	}()

	defer func() {
		cancel()
		require.NoError(t, testEnv.Stop())
	}()

	// wait for k8s client to be ready
	require.Eventually(t, func() bool {
		return controller.k8sClient != nil
	}, defaultWait, defaultTick)

	// create test secrets
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-secret-1",
		},
		Data: map[string][]byte{
			clientSecretKey: []byte("fake-client-secret-1"),
		},
	}
	require.NoError(t, controller.k8sClient.Create(ctx, secret))
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-secret-2",
		},
		Data: map[string][]byte{
			clientSecretKey: []byte("fake-client-secret-2"),
		},
	}
	require.NoError(t, controller.k8sClient.Create(ctx, secret))

	// wait for the secret controller to update the configuration
	require.Eventually(t, func() bool {
		return proto.Equal(originalConf, effectiveConf)
	}, defaultWait, defaultTick)
}

func startEnv(t *testing.T) (*envtest.Environment, *rest.Config) {
	ctrl.SetLogger(log.NewLogrAdapter(internal.Logger(internal.K8s)))
	env := &envtest.Environment{}
	cfg, err := env.Start()
	require.NoError(t, err)
	return env, cfg
}
