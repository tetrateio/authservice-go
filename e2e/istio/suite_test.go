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

package istio

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applycorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	applymetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/tetrateio/authservice-go/e2e"
)

const (
	istiodConfig  = "cluster/istiod-config.yaml"
	istioGwConfig = "cluster/istiogw-config.yaml"
	manifestsDir  = "cluster/manifests"
)

// testManifests contains the list of manifests that will be deployed in the cluster before running the e2e tests
var testManifests = []string{
	"keycloak.yaml",
	"redis.yaml",
	"authservice.yaml",
	"http-echo.yaml",
	"ingress-gateway.yaml",
	"authz-policy.yaml",
	"telemetry.yaml",
}

// istioInstall contains the commands to install Istio using Helm, so we don't require
// downloading `istioctl` or other tooling that would just make the e2e tests take more time.
var istioInstall = []string{
	"helm repo add istio https://istio-release.storage.googleapis.com/charts --force-update",
	"helm repo update istio",
	fmt.Sprintf("helm --kubeconfig %s install istio-base istio/base -n istio-system --create-namespace", e2e.KubeConfig),
	fmt.Sprintf("helm --kubeconfig %s install istiod istio/istiod -n istio-system -f %s --wait", e2e.KubeConfig, istiodConfig),
	fmt.Sprintf("helm --kubeconfig %s install istio-ingress istio/gateway -n istio-system -f %s --wait", e2e.KubeConfig, istioGwConfig),
}

// IstioSuite is a suite that installs Istio in the Kubernetes cluster and runs tests against it.
type IstioSuite struct {
	e2e.K8sSuite
}

func TestIstio(t *testing.T) {
	suite.Run(t, &IstioSuite{})
}

// SetupSuite initializes the Kubernetes clients, installs Istio in the cluster and waits until the
// services are up and running.
func (i *IstioSuite) SetupSuite() {
	i.K8sSuite.SetupSuite()

	client, err := kubernetes.NewForConfig(i.Kubeconfig)
	i.Require().NoError(err)

	// If Istio is already installed, just return and do not try to install it again
	// and make e2e tests easier to run multiple times without tearing down the entire
	// environment
	if !i.istioInstalled(client) {
		i.installistio()
	}

	i.installKeycloakCerts()

	i.T().Log("deploying the test services...")
	for _, f := range testManifests {
		i.MustApply(context.Background(), manifestsDir+"/"+f)
	}
	i.WaitForPods(client, "keycloak", "job-name=setup-keycloak", corev1.PodSucceeded, e2e.PodInitialized)
	i.WaitForPods(client, "redis", "", corev1.PodRunning, e2e.PodReady)
	i.WaitForPods(client, "authservice", "", corev1.PodRunning, e2e.PodReady)
	i.WaitForPods(client, "http-echo", "", corev1.PodRunning, e2e.PodReady)
}

func (i *IstioSuite) installistio() {
	i.T().Log("installing Istio...")

	for _, cmd := range istioInstall {
		parts := strings.Split(cmd, " ")
		out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
		i.Require().NoError(err, string(out))
	}
}

func (i *IstioSuite) istioInstalled(client kubernetes.Interface) bool {
	_, err := client.CoreV1().Services("istio-system").Get(context.Background(), "istiod", metav1.GetOptions{})
	return err == nil
}

// Install the Keycloak CA certificate in the cluster
func (i *IstioSuite) installKeycloakCerts() {
	// load the Keycloak certificates
	ca, err := os.ReadFile("certs/ca.crt")
	i.Require().NoError(err)
	cert, err := os.ReadFile("certs/keycloak.keycloak.crt")
	i.Require().NoError(err)
	key, err := os.ReadFile("certs/keycloak.keycloak.key")
	i.Require().NoError(err)

	// Create the secret with the Keycloak certificates in the "keycloak" namespace
	i.applyNamespace("keycloak")
	i.applySecret("keycloak-certs", "keycloak", corev1.SecretTypeTLS, map[string][]byte{"ca.crt": ca, "tls.crt": cert, "tls.key": key})

	// Create the secret with the Keycloak CA in the "authservice" namespace
	i.applyNamespace("authservice")
	i.applySecret("keycloak-ca", "authservice", corev1.SecretTypeOpaque, map[string][]byte{"ca.crt": ca})
}

func (i *IstioSuite) applyNamespace(name string) {
	k8sClient, err := v1.NewForConfig(i.Kubeconfig)
	i.Require().NoError(err)

	var (
		namespaceKind = "Namespace"
		namespaceAPI  = "v1"
	)

	namespace := &applycorev1.NamespaceApplyConfiguration{
		TypeMetaApplyConfiguration:   applymetav1.TypeMetaApplyConfiguration{Kind: &namespaceKind, APIVersion: &namespaceAPI},
		ObjectMetaApplyConfiguration: &applymetav1.ObjectMetaApplyConfiguration{Name: &name},
	}
	_, err = k8sClient.Namespaces().Apply(context.Background(), namespace, metav1.ApplyOptions{FieldManager: "e2e"})
	i.Require().NoError(err)
}

func (i *IstioSuite) applySecret(name, namespace string, secretType corev1.SecretType, data map[string][]byte) {
	k8sClient, err := v1.NewForConfig(i.Kubeconfig)
	i.Require().NoError(err)

	var (
		secretKind = "Secret"
		secretAPI  = "v1"
	)
	secret := &applycorev1.SecretApplyConfiguration{
		TypeMetaApplyConfiguration:   applymetav1.TypeMetaApplyConfiguration{Kind: &secretKind, APIVersion: &secretAPI},
		ObjectMetaApplyConfiguration: &applymetav1.ObjectMetaApplyConfiguration{Name: &name, Namespace: &namespace},
		Data:                         data,
		Type:                         &secretType,
	}
	_, err = k8sClient.Secrets(namespace).Apply(context.Background(), secret, metav1.ApplyOptions{FieldManager: "e2e"})
	i.Require().NoError(err)
}
