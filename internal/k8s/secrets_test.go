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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSecretReader(t *testing.T) {
	validSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "test-secret",
		},
		Data: map[string][]byte{
			"key": []byte("fake-client-secret"),
		},
	}
	invalidSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "invalid-secret",
		},
		Data: map[string][]byte{
			"invalid-key": []byte("fake-client-secret"),
		},
	}

	kubeClient := fake.NewClientBuilder().WithObjects(validSecret, invalidSecret).Build()

	tests := []struct {
		caseName   string
		name       string
		namespace  string
		key        string
		wantErr    error
		wantSecret string
	}{
		{
			caseName:   "valid secret",
			name:       "test-secret",
			namespace:  "default",
			key:        "key",
			wantSecret: "fake-client-secret",
		},
		{
			caseName: "invalid secret",
			name:     "invalid-secret",
			key:      "key",
			wantErr:  ErrNoSecretData,
		},
		{
			caseName: "no existing secret",
			name:     "non-existing-secret",
			key:      "key",
			wantErr:  ErrGetSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.caseName, func(t *testing.T) {
			sr := NewSecretReader(kubeClient, tt.name, tt.namespace, tt.key)
			got, err := sr.Read()
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantSecret, string(got))
		})
	}
}

func TestSecretReader_ID(t *testing.T) {
	sr := NewSecretReader(nil, "name", "namespace", "key")
	require.Equal(t, "k8s-secret-(namespace/name)", sr.ID())

	sr = NewSecretReader(nil, "name", "", "key")
	require.Equal(t, "k8s-secret-(default/name)", sr.ID())
}
