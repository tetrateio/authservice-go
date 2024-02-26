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

package tls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal/k8s"
)

const (
	invalidCAPem      = `<invalid ca.pem>`
	firstCertDNSName  = "first"
	secondCertDNSName = "second"

	firstCAPem = `-----BEGIN CERTIFICATE-----
MIICMjCCAdygAwIBAgIUfjMuIL07OwG1Q13HGhaDJbdKgRYwDQYJKoZIhvcNAQEL
BQAwWjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ4wDAYDVQQDDAVmaXJzdDAg
Fw0yNDAyMjUwNzU5MjhaGA8zMDA0MDQyODA3NTkyOFowWjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB1RldHJhdGUxFDASBgNVBAsM
C0VuZ2luZWVyaW5nMQ4wDAYDVQQDDAVmaXJzdDBcMA0GCSqGSIb3DQEBAQUAA0sA
MEgCQQDFT3pCjZyxnQ5o46GlBd7e6yredUuGdYhaLPjkcDZw5LTdy/WdJ8MRsUdJ
uh0v5HSpDsd6yIiP8SF20WgfbYpfAgMBAAGjeDB2MB0GA1UdDgQWBBQUQOM/blzh
GpovGudMO43BZSKjTjAfBgNVHSMEGDAWgBQUQOM/blzhGpovGudMO43BZSKjTjAS
BgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIC5DAQBgNVHREECTAHggVm
aXJzdDANBgkqhkiG9w0BAQsFAANBAG0Gwgwaxe+OnpFOdDi0QFILN10EFl0BsNjz
JROKsQSnX5sGlYdVcb0TBAf8MojqNZvq78C1fCXkDus3g3AZyLM=
-----END CERTIFICATE-----`

	firstCertPem = `-----BEGIN CERTIFICATE-----
MIICDjCCAbigAwIBAgIUQPCzOs6M9RxopgX0HL8uJKDoBpowDQYJKoZIhvcNAQEL
BQAwWjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ4wDAYDVQQDDAVmaXJzdDAg
Fw0yNDAyMjUwNzU5MjhaGA8zMDA0MDQyODA3NTkyOFowWjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoMB1RldHJhdGUxFDASBgNVBAsM
C0VuZ2luZWVyaW5nMQ4wDAYDVQQDDAVmaXJzdDBcMA0GCSqGSIb3DQEBAQUAA0sA
MEgCQQCm/7/RmxYPmRmtoWmD4U6Gv9x96ApW3Wf2yvl5o7J4StvgRSreTBjQO59N
ERwfhAcNV+SRZWIXtodmhryCcbNzAgMBAAGjVDBSMBAGA1UdEQQJMAeCBWZpcnN0
MB0GA1UdDgQWBBRczCCJnGGmj/mK8ncpBM4cYX4hoDAfBgNVHSMEGDAWgBQUQOM/
blzhGpovGudMO43BZSKjTjANBgkqhkiG9w0BAQsFAANBAEynBzYcUtn1LgUnbXnq
UCQC5/a5NavSwD+uujen++9luWxZP5BDLIuqWVEkVeavaRD8WTNi6pB/4Kok3/h7
mrU=
-----END CERTIFICATE-----`

	secondCAPem = `-----BEGIN CERTIFICATE-----
MIICNTCCAd+gAwIBAgIUSNiQbnskpJz9qXIy3ZvyeBr5DgswDQYJKoZIhvcNAQEL
BQAwWzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ8wDQYDVQQDDAZzZWNvbmQw
IBcNMjQwMjI1MDc1ODA4WhgPMzAwNDA0MjgwNzU4MDhaMFsxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMRAwDgYDVQQKDAdUZXRyYXRlMRQwEgYDVQQL
DAtFbmdpbmVlcmluZzEPMA0GA1UEAwwGc2Vjb25kMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAMz0bgSTGkUT4BevyrQUBI11ISf4sORB4iIOBeZxF9T3+k7fOqCieok7
KquH6X7gsmL/A15qU0XCsVZWZ9ro9/UCAwEAAaN5MHcwHQYDVR0OBBYEFMO6IIAi
fGtfQdEJpC+IrTQqcbfoMB8GA1UdIwQYMBaAFMO6IIAifGtfQdEJpC+IrTQqcbfo
MBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgLkMBEGA1UdEQQKMAiC
BnNlY29uZDANBgkqhkiG9w0BAQsFAANBADGCBvNWs7L+uMYHvfk5Uy+P6eoIJKok
LeXeAdsKK+0F9xCmnNfuinTJ1ioZ47e7fFS2XGfO8qSmmb0wVnK/9Ig=
-----END CERTIFICATE-----`

	secondCertPem = `-----BEGIN CERTIFICATE-----
MIICETCCAbugAwIBAgIUXHZGY3lT62cY3Y/ccIoRAp7P5mkwDQYJKoZIhvcNAQEL
BQAwWzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAoM
B1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQ8wDQYDVQQDDAZzZWNvbmQw
IBcNMjQwMjI1MDc1ODA4WhgPMzAwNDA0MjgwNzU4MDhaMFsxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMRAwDgYDVQQKDAdUZXRyYXRlMRQwEgYDVQQL
DAtFbmdpbmVlcmluZzEPMA0GA1UEAwwGc2Vjb25kMFwwDQYJKoZIhvcNAQEBBQAD
SwAwSAJBAOgoDZ6wH/7lbqGphAOlJqRJcWeaN4jB8BEc/MejG1UL75uFnwXDmwDH
KNU1e3VygpWyFwrrBKde4DEMBKnBdPsCAwEAAaNVMFMwEQYDVR0RBAowCIIGc2Vj
b25kMB0GA1UdDgQWBBTxli7ulcoMhJPUGTNS0qclcCd41DAfBgNVHSMEGDAWgBTD
uiCAInxrX0HRCaQviK00KnG36DANBgkqhkiG9w0BAQsFAANBAIdc1uTnNDMdROp4
fIGuGu2HAHkqnBhOHh71Xd/WD/9kjPGUQNzRZUYaWs9EGz95VvcrSIPPMU8tLhIt
dabJiLY=
-----END CERTIFICATE-----`
)

func TestLoadTLSConfig(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		validFile   = tmpDir + "/valid.pem"
		invalidFile = tmpDir + "/invalid.pem"
	)
	require.NoError(t, os.WriteFile(validFile, []byte(firstCAPem), 0644))
	require.NoError(t, os.WriteFile(invalidFile, []byte(invalidCAPem), 0644))

	var (
		validSecretName   = "test-secret"
		invalidSecretName = "invalid-secret"

		validSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: validSecretName},
			Data:       map[string][]byte{"ca.crt": []byte(firstCAPem)},
		}
		invalidSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: invalidSecretName},
			Data:       map[string][]byte{"no-valid-key": []byte(invalidCAPem)},
		}
	)

	kubeClient := fake.NewClientBuilder().WithObjects(validSecret, invalidSecret).Build()

	tests := []struct {
		name     string
		config   Config
		wantTLS  bool
		wantSkip bool
		wantPool bool
		wantErr  bool
	}{
		{
			name:    "no CA config",
			config:  &oidc.OIDCConfig{},
			wantTLS: false,
		},
		{
			name:     "skip verify config",
			config:   &oidc.OIDCConfig{SkipVerifyPeerCert: structpb.NewBoolValue(true)},
			wantTLS:  true,
			wantSkip: true,
		},
		{
			name:     "valid trusted CA string config",
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: firstCAPem}},
			wantTLS:  true,
			wantPool: true,
		},
		{
			name:    "invalid trusted CA string config",
			config:  &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthority{TrustedCertificateAuthority: invalidCAPem}},
			wantErr: true,
		},
		{
			name:     "valid trusted CA file config",
			config:   &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: validFile}},
			wantTLS:  true,
			wantPool: true,
		},
		{
			name:    "invalid trusted CA file config",
			config:  &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: invalidFile}},
			wantErr: true,
		},
		{
			name:    "no existing file trusted CA file config",
			config:  &oidc.OIDCConfig{TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: "non-existing.pem"}},
			wantErr: true,
		},
		{
			name: "valid trusted CA file and skip verify config",
			config: &oidc.OIDCConfig{
				TrustedCaConfig:    &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: validFile},
				SkipVerifyPeerCert: structpb.NewBoolValue(true),
			},
			wantTLS:  true,
			wantSkip: false, // skip verify is ignored because there's a trusted CA
			wantPool: true,
		},
		{
			name: "valid trusted CA secret config",
			config: &oidc.OIDCConfig{
				TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthoritySecret{
					TrustedCertificateAuthoritySecret: &oidc.OIDCConfig_SecretReference{
						Name: validSecretName,
					},
				},
			},
			wantTLS:  true,
			wantPool: true,
		},
		{
			name: "invalid trusted CA secret config",
			config: &oidc.OIDCConfig{
				TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthoritySecret{
					TrustedCertificateAuthoritySecret: &oidc.OIDCConfig_SecretReference{
						Name: invalidSecretName,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no existing secret trusted CA secret config",
			config: &oidc.OIDCConfig{
				TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthoritySecret{
					TrustedCertificateAuthoritySecret: &oidc.OIDCConfig_SecretReference{
						Name: validSecretName, Namespace: "non-existing", // non-existing namespace causes the secret to not exist
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			pool := NewTLSConfigPool(ctx, &mockK8sLoader{Client: kubeClient})
			t.Cleanup(cancel)

			got, err := pool.LoadTLSConfig(tc.config)

			// Check for errors
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)

			// Check for expected TLS config
			if !tc.wantTLS {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tc.wantSkip, got.InsecureSkipVerify)
			require.Equal(t, tc.wantPool, got.RootCAs != nil)
		})
	}
}

func TestTLSConfigPoolUpdates(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		caFile       = tmpDir + "/ca1.pem"
		caSecretName = "ca-secret"
	)

	block, _ := pem.Decode([]byte(firstCertPem))
	cert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode([]byte(secondCertPem))
	cert2, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	k8sClient := fake.NewClientBuilder().Build()
	pool := NewTLSConfigPool(ctx, &mockK8sLoader{Client: k8sClient})
	t.Cleanup(cancel)

	const (
		interval        = 100 * time.Millisecond
		intervalAndHalf = interval + interval/2
	)

	cases := []struct {
		name       string
		config     *oidc.OIDCConfig
		createData func(data string) error
		updateData func(data string) error
		removeData func() error
	}{
		{
			name: "trusted CA file",
			config: &oidc.OIDCConfig{
				TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: caFile},
				TrustedCertificateAuthorityRefreshInterval: durationpb.New(interval),
			},
			createData: func(data string) error {
				return os.WriteFile(caFile, []byte(data), 0644)
			},
			updateData: func(data string) error {
				return os.WriteFile(caFile, []byte(data), 0644)
			},
			removeData: func() error {
				return os.Remove(caFile)
			},
		},
		{
			name: "trusted CA secret",
			config: &oidc.OIDCConfig{
				TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthoritySecret{
					TrustedCertificateAuthoritySecret: &oidc.OIDCConfig_SecretReference{
						Name: caSecretName, Namespace: "the-namespace",
					},
				},
				TrustedCertificateAuthorityRefreshInterval: durationpb.New(interval),
			},
			createData: func(data string) error {
				return k8sClient.Create(context.Background(),
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: "the-namespace", Name: caSecretName},
						Data:       map[string][]byte{"ca.crt": []byte(firstCAPem)},
					})
			},
			updateData: func(data string) error {
				secret := &corev1.Secret{}
				if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "the-namespace", Name: caSecretName}, secret); err != nil {
					return err
				}
				secret.Data["ca.crt"] = []byte(data)
				return k8sClient.Update(context.Background(), secret)
			},
			removeData: func() error {
				secret := &corev1.Secret{}
				err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: "the-namespace", Name: caSecretName}, secret)
				if err != nil {
					return err
				}
				return k8sClient.Delete(context.Background(), secret)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// setup the initial data
			require.NoError(t, tc.createData(firstCAPem))

			// load the TLS config
			gotTLS, err := pool.LoadTLSConfig(tc.config)
			require.NoError(t, err)
			require.NotNil(t, gotTLS)

			// verify the got TLS config is valid
			_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
			require.NoError(t, err)

			// update the CA file content
			require.NoError(t, tc.updateData(secondCAPem))
			time.Sleep(intervalAndHalf)

			// load the TLS config again
			gotTLS, err = pool.LoadTLSConfig(tc.config)
			require.NoError(t, err)

			// verify the got TLS config is not valid anymore for the old CA,
			// as we updated it with CA only valid for cert2.
			_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
			require.Error(t, err)

			// verify the got TLS config is valid for the new CA
			_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: secondCertDNSName})
			require.NoError(t, err)

			// update the CA file content to be invalid
			require.NoError(t, tc.updateData(invalidCAPem))
			time.Sleep(intervalAndHalf)

			// load the TLS config again
			gotTLS, err = pool.LoadTLSConfig(tc.config)
			require.NoError(t, err)

			// verify the config is not updated, so the old TLS config is still valid
			_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: secondCertDNSName})
			require.NoError(t, err)

			// remove the CA file
			require.NoError(t, tc.removeData())
			time.Sleep(intervalAndHalf)

			// load the TLS config again
			gotTLS, err = pool.LoadTLSConfig(tc.config)
			require.NoError(t, err)

			// verify the config is not modified, so the old TLS config is still valid
			_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: secondCertDNSName})
			require.NoError(t, err)

			// update the CA file content to be valid again and verify the new CA is loaded
			require.NoError(t, tc.createData(firstCAPem))
			time.Sleep(intervalAndHalf)

			// load the TLS config again
			gotTLS, err = pool.LoadTLSConfig(tc.config)
			require.NoError(t, err)

			_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS.RootCAs, DNSName: firstCertDNSName})
			require.NoError(t, err)
		})
	}
}

func TestTLSConfigPoolWithMultipleConfigs(t *testing.T) {
	tmpDir := t.TempDir()
	var (
		caFile1 = tmpDir + "/ca1.pem"
		caFile2 = tmpDir + "/ca2.pem"
	)
	require.NoError(t, os.WriteFile(caFile1, []byte(firstCAPem), 0644))
	require.NoError(t, os.WriteFile(caFile2, []byte(secondCAPem), 0644))

	block, _ := pem.Decode([]byte(firstCertPem))
	cert1, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	block, _ = pem.Decode([]byte(secondCertPem))
	cert2, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	pool := NewTLSConfigPool(ctx, &mockK8sLoader{})
	t.Cleanup(cancel)

	const (
		config1Interval = 100 * time.Millisecond
		config2Interval = 200 * time.Millisecond
	)
	var intervalAndHalf = func(interval time.Duration) time.Duration { return interval + interval/2 }

	config1 := &oidc.OIDCConfig{
		TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: caFile1},
		TrustedCertificateAuthorityRefreshInterval: durationpb.New(config1Interval),
	}
	config2 := &oidc.OIDCConfig{
		TrustedCaConfig: &oidc.OIDCConfig_TrustedCertificateAuthorityFile{TrustedCertificateAuthorityFile: caFile2},
		TrustedCertificateAuthorityRefreshInterval: durationpb.New(config2Interval),
	}

	// load the TLS config for config1
	gotTLS1, err := pool.LoadTLSConfig(config1)
	require.NoError(t, err)

	// load the TLS config for config2
	gotTLS2, err := pool.LoadTLSConfig(config2)
	require.NoError(t, err)

	// verify the got TLS config for config1 is valid
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS1.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)

	// verify the got TLS config for config2 is valid
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS2.RootCAs, DNSName: secondCertDNSName})
	require.NoError(t, err)

	// update the second file to contain the first CA
	require.NoError(t, os.WriteFile(caFile2, []byte(firstCAPem), 0644))
	time.Sleep(intervalAndHalf(config2Interval))

	// load the TLS config for config2 again
	gotTLS2, err = pool.LoadTLSConfig(config2)
	require.NoError(t, err)

	// verify the got TLS config for config2 is valid for the first CA and not for the second
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS2.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)
	_, err = cert2.Verify(x509.VerifyOptions{Roots: gotTLS2.RootCAs, DNSName: secondCertDNSName})
	require.Error(t, err)

	// verify the got TLS config for config1 is still valid
	gotTLS1, err = pool.LoadTLSConfig(config1)
	require.NoError(t, err)
	_, err = cert1.Verify(x509.VerifyOptions{Roots: gotTLS1.RootCAs, DNSName: firstCertDNSName})
	require.NoError(t, err)
}

var _ k8s.ClientLoader = &mockK8sLoader{}

type mockK8sLoader struct {
	client.Client
}

func (m mockK8sLoader) Name() string       { return "mock-k8s-loader" }
func (m mockK8sLoader) Get() client.Client { return m.Client }
