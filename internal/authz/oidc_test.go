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

package authz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/run"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/test/bufconn"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	inthttp "github.com/tetrateio/authservice-go/internal/http"
	"github.com/tetrateio/authservice-go/internal/oidc"
)

var (
	callbackRequest = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "localhost:443", Path: "/callback?code=auth-code&state=new-state",
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}

	noSessionRequest = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "example.com", Path: "/",
					Method: "GET",
				},
			},
		},
	}

	withSessionHeader = &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "example.com", Path: "/",
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}

	requestedAppURL = "https://localhost:443/final-app"
	validAuthState  = &oidc.AuthorizationState{
		Nonce:        newNonce,
		State:        newState,
		RequestedURL: requestedAppURL,
	}

	yesterday = time.Now().Add(-24 * time.Hour)
	tomorrow  = time.Now().Add(24 * time.Hour)

	sessionID    = "test-session-id"
	newSessionID = "new-session-id"
	newNonce     = "new-nonce"
	newState     = "new-state"

	basicOIDCConfig = &oidcv1.OIDCConfig{
		IdToken: &oidcv1.TokenConfig{
			Header:   "Authorization",
			Preamble: "Bearer",
		},
		AccessToken: &oidcv1.TokenConfig{
			Header:   "X-Access-Token",
			Preamble: "Bearer",
		},
		TokenUri:         "http://idp-test-server/token",
		AuthorizationUri: "http://idp-test-server/auth",
		CallbackUri:      "https://localhost:443/callback",
		ClientId:         "test-client-id",
		ClientSecret:     "test-client-secret",
		Scopes:           []string{"openid", "email"},
	}

	dynamicOIDCConfig = &oidcv1.OIDCConfig{
		IdToken: &oidcv1.TokenConfig{
			Header:   "Authorization",
			Preamble: "Bearer",
		},
		AccessToken: &oidcv1.TokenConfig{
			Header:   "X-Access-Token",
			Preamble: "Bearer",
		},
		ConfigurationUri: "http://idp-test-server/.well-known/openid-configuration",
		CallbackUri:      "https://localhost:443/callback",
		ClientId:         "test-client-id",
		ClientSecret:     "test-client-secret",
		Scopes:           []string{"openid", "email"},
	}

	wellKnownURIs = `
{
	"issuer": "http://idp-test-server",
	"authorization_endpoint": "http://idp-test-server/authorize",
	"token_endpoint": "http://idp-test-server/token",
	"jwks_uri": "http://idp-test-server/jwks"
}`
)

func TestOIDCProcess(t *testing.T) {
	require.NoError(t, internal.NewLogSystem(&testLogger{level: telemetry.LevelDebug}, &configv1.Config{LogLevel: "debug"}).(run.PreRunner).PreRun())

	wantRedirectParams := url.Values{}
	wantRedirectParams.Add("response_type", "code")
	wantRedirectParams.Add("client_id", "test-client-id")
	wantRedirectParams.Add("redirect_uri", "https://localhost:443/callback")
	wantRedirectParams.Add("scope", "openid email")
	wantRedirectParams.Add("state", newState)
	wantRedirectParams.Add("nonce", newNonce)
	wantRedirectBaseURI := "http://idp-test-server/auth"

	unknownJWKPriv, _ := newKeyPair(t)
	jwkPriv, jwkPub := newKeyPair(t)
	bytes, err := json.Marshal(newKeySet(jwkPub))
	require.NoError(t, err)
	basicOIDCConfig.JwksConfig = &oidcv1.OIDCConfig_Jwks{
		Jwks: string(bytes),
	}

	clock := oidc.Clock{}
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
	store := sessions.Get(basicOIDCConfig)
	h, err := NewOIDCHandler(basicOIDCConfig, oidc.NewJWKSProvider(), sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState))
	require.NoError(t, err)
	log := h.(*oidcHandler).log.(*testLogger)

	ctx := context.Background()

	// The following subset of tests is testing the requests to the app, not any callback or auth flow.
	// So there's no expected communication with any external server.

	requestToAppTests := []struct {
		name                string
		req                 *envoy.CheckRequest
		storedTokenResponse *oidc.TokenResponse
		responseVerify      func(*testing.T, *envoy.CheckResponse)
	}{
		{
			name: "invalid request with missing http",
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				log.requireLog(t, "missing http in the request")
			},
		},
		{
			name: "request with no sessionID",
			req:  noSessionRequest,
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				// A new authorization state should have been set in the store
				requireStoredState(t, store, newSessionID, true)
				log.requireLog(t, "session id cookie is missing", "cookie-name", defaultCookieName)
				log.requireLog(t, "No session cookie detected. Generating new session and sending user to re-authenticate.")
			},
		},
		{
			name: "request with no existing sessionID",
			req:  withSessionHeader,
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				// A new authorization state should have been set in the store
				requireStoredState(t, store, newSessionID, true)
				// The old one should have been removed
				requireStoredState(t, store, sessionID, false)
				log.requireLog(t, "Required tokens are not present. Sending user to re-authenticate.")
			},
		},
		{
			name: "request with an existing sessionID expired",
			req:  withSessionHeader,
			storedTokenResponse: &oidc.TokenResponse{
				IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday)),
				AccessToken:          "access-token",
				AccessTokenExpiresAt: yesterday,
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), wantRedirectBaseURI, wantRedirectParams)
				requireCookie(t, resp.GetDeniedResponse())
				// A new authorization state should have been set in the store
				requireStoredState(t, store, newSessionID, true)
				// The old one should have been removed
				requireStoredState(t, store, sessionID, false)
				log.requireLog(t, "A token was expired, but session did not contain a refresh token. Sending user to re-authenticate.")
			},
		},
		{
			name: "request with an existing sessionID not expired",
			req:  withSessionHeader,
			storedTokenResponse: &oidc.TokenResponse{
				IDToken:              newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
				AccessToken:          "access-token",
				AccessTokenExpiresAt: tomorrow,
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), basicOIDCConfig, newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)), "access-token")
				// The sessionID should not have been changed
				requireStoredTokens(t, store, sessionID, true)
				requireStoredState(t, store, newSessionID, false)
				requireStoredTokens(t, store, newSessionID, false)
				log.requireLog(t, "Tokens not expired. Allowing request to proceed.")
			},
		},
	}

	for _, tt := range requestToAppTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, store.RemoveSession(ctx, sessionID))
				require.NoError(t, store.RemoveSession(ctx, newSessionID))
				log.clear()
			})

			if tt.storedTokenResponse != nil {
				require.NoError(t, store.SetTokenResponse(ctx, sessionID, tt.storedTokenResponse))
			}

			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, tt.req, resp))
			tt.responseVerify(t, resp)
		})
	}

	// The following subset of tests is testing the callback requests, so there's expected communication with the IDP server.

	idpServer := newServer()
	h.(*oidcHandler).httpClient = idpServer.newHTTPClient()

	callbackTests := []struct {
		name               string
		req                *envoy.CheckRequest
		storedAuthState    *oidc.AuthorizationState
		mockTokensResponse *tokensResponse
		mockStatusCode     int
		responseVerify     func(*testing.T, *envoy.CheckResponse)
	}{
		{
			name:            "successfully retrieve new tokens",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), requestedAppURL, nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "request is invalid, query parameters are missing",
			req:  modifyCallbackRequestPath("/callback?"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "form data is invalid, no query parameters found", "query", "")
			},
		},
		{
			name: "request is invalid, query has invalid format",
			req:  modifyCallbackRequestPath("/callback?invalid;format"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "error parsing query", "query", "invalid;format")
			},
		},
		{
			name: "request is invalid, state is missing",
			req:  modifyCallbackRequestPath("/callback?code=auth-code"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "form data is invalid, missing state or code", "state", "", "code", "auth-code")
			},
		},
		{
			name: "request is invalid, code is missing",
			req:  modifyCallbackRequestPath("/callback?state=new-state"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "form data is invalid, missing state or code", "state", "new-state", "code", "")
			},
		},
		{
			name: "session state not found in the store",
			req:  callbackRequest,
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				require.Equal(t, typev3.StatusCode_BadRequest, response.GetDeniedResponse().GetStatus().GetCode())
				require.Equal(t, "Oops, your session has expired. Please try again.", response.GetDeniedResponse().GetBody())
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "missing state, nonce, and original url requested by user in the store. Cannot redirect.")
			},
		},
		{
			name: "session state stored does not match the request",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        newNonce,
				State:        "non-matching-state",
				RequestedURL: requestedAppURL,
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "state from request does not match state from store", "state-from-request", newState, "state-from-store", "non-matching-state")
			},
		},
		{
			name:            "idp server returns non-200 status code",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockStatusCode:  http.StatusInternalServerError,
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unknown), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "OIDC server returned non-200 status code")
			},
		},
		{
			name:            "idp server returns empty body",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockStatusCode:  http.StatusOK,
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "error unmarshalling tokens response")
			},
		},
		{
			name:            "idp server returns invalid JWT id-token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockStatusCode:  http.StatusOK,
			mockTokensResponse: &tokensResponse{
				IDToken: "not-a-jwt",
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "error parsing id token")
			},
		},
		{
			name:            "idp server returns JWT signed with unknown key",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, unknownJWKPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Internal), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "error verifying id token with fetched jwks")
			},
		},
		{
			name: "session nonce stored does idp returned nonce",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        "old-nonce",
				State:        newState,
				RequestedURL: requestedAppURL,
			},
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", "non-matching-nonce")),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "id token nonce does not match", "nonce-from-store", "old-nonce", "nonce-from-id-token", "non-matching-nonce")
			},
		},
		{
			name:            "idp returned empty audience",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce)),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "id token audience does not match", "aud-from-id-token", []string(nil))
			},
		},
		{
			name:            "idp returned non-matching audience",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"non-matching-audience"})),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "id token audience does not match", "aud-from-id-token", []string{"non-matching-audience"})
			},
		},
		{
			name:            "idp returned non-bearer token type",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:   newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"test-client-id"})),
				TokenType: "not-bearer",
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "token type is not Bearer in token response")
			},
		},
		{
			name:            "idp returned invalid expires_in for access token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:   newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"test-client-id"})),
				TokenType: "Bearer",
				ExpiresIn: -1,
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "expires_in is not a positive value in token response", "expires-in", -1)
			},
		},
		{
			name:            "idp didn't return access token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:   newJWT(t, jwkPriv, jwt.NewBuilder().Claim("nonce", newNonce).Audience([]string{"test-client-id"})),
				TokenType: "Bearer",
				ExpiresIn: 3600,
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
				log.requireLog(t, "access token forwarding is configured but no access token was returned")
			},
		},
	}

	for _, tt := range callbackTests {
		t.Run("request matches callback: "+tt.name, func(t *testing.T) {
			idpServer.Start()
			t.Cleanup(func() {
				idpServer.Stop()
				require.NoError(t, store.RemoveSession(ctx, sessionID))
				log.clear()
			})

			idpServer.tokensResponse = tt.mockTokensResponse
			idpServer.statusCode = tt.mockStatusCode
			if tt.mockStatusCode <= 0 {
				idpServer.statusCode = http.StatusOK
			}

			// Set the authorization state in the store, so it can be found by the handler
			require.NoError(t, store.SetAuthorizationState(ctx, sessionID, tt.storedAuthState))

			resp := &envoy.CheckResponse{}
			err = h.Process(ctx, tt.req, resp)
			require.NoError(t, err)

			tt.responseVerify(t, resp)
		})
	}
}

func TestOIDCProcessWithFailingSessionStore(t *testing.T) {
	require.NoError(t, internal.NewLogSystem(&testLogger{level: telemetry.LevelDebug}, &configv1.Config{LogLevel: "debug"}).(run.PreRunner).PreRun())
	store := &storeMock{delegate: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}
	sessions := &mockSessionStoreFactory{store: store}

	jwkPriv, jwkPub := newKeyPair(t)
	bytes, err := json.Marshal(newKeySet(jwkPub))
	require.NoError(t, err)
	basicOIDCConfig.JwksConfig = &oidcv1.OIDCConfig_Jwks{
		Jwks: string(bytes),
	}

	h, err := NewOIDCHandler(basicOIDCConfig, oidc.NewJWKSProvider(), sessions, oidc.Clock{}, oidc.NewStaticGenerator(newSessionID, newNonce, newState))
	require.NoError(t, err)
	log := h.(*oidcHandler).log.(*testLogger)

	ctx := context.Background()

	// The following subset of tests is testing the requests to the app, not any callback or auth flow.
	// So there's no expected communication with any external server.
	requestToAppTests := []struct {
		name        string
		storeErrors map[int]bool
		wantLogs    [][]interface{}
	}{
		{
			name:        "app request - fails to get token response from given session ID",
			storeErrors: map[int]bool{getTokenResponse: true},
			wantLogs: [][]interface{}{
				{"attempting session retrieval", "session-id", sessionID},
				{"error retrieving tokens from session store", "session-id", sessionID},
			},
		},
		{
			name:        "app request (redirect to IDP) - fails to remove old session",
			storeErrors: map[int]bool{removeSession: true},
			wantLogs: [][]interface{}{
				{"attempting session retrieval", "session-id", sessionID},
				{"Required tokens are not present. Sending user to re-authenticate.", "session-id", sessionID},
				{"error removing old session", "session-id", sessionID},
			},
		},
		{
			name:        "app request (redirect to IDP) - fails to set new authorization state",
			storeErrors: map[int]bool{setAuthorizationState: true},
			wantLogs: [][]interface{}{
				{"attempting session retrieval", "session-id", sessionID},
				{"Required tokens are not present. Sending user to re-authenticate.", "session-id", sessionID},
				{"error storing the new authorization state", "session-id", sessionID},
			},
		},
	}

	for _, tt := range requestToAppTests {
		t.Run(tt.name, func(t *testing.T) {
			store.errs = tt.storeErrors
			t.Cleanup(func() {
				store.errs = nil
				log.clear()
			})
			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, withSessionHeader, resp))
			requireSessionErrorResponse(t, resp)
			for _, wantLog := range tt.wantLogs {
				log.requireLog(t, wantLog[0].(string), wantLog[1:]...)
			}
		})
	}

	idpServer := newServer()
	idpServer.statusCode = http.StatusOK
	idpServer.tokensResponse = &tokensResponse{
		IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
		AccessToken: "access-token",
		TokenType:   "Bearer",
	}
	idpServer.Start()
	t.Cleanup(idpServer.Stop)
	h.(*oidcHandler).httpClient = idpServer.newHTTPClient()

	// The following subset of tests is testing the callback requests, so there's expected communication with the IDP server.
	// The store is expected to fail in some way, so the handler should return an error response.
	callbackTests := []struct {
		name              string
		storeCallsToError map[int]bool
		wantLogs          [][]interface{}
	}{
		{
			name:              "callback request - fails to get authorization state",
			storeCallsToError: map[int]bool{getAuthorizationState: true},
			wantLogs: [][]interface{}{
				{"handling callback request"},
				{"error retrieving authorization state from session store", "session-id", sessionID},
			},
		},
		{
			name:              "callback request - fails to clear old authorization state",
			storeCallsToError: map[int]bool{clearAuthorizationState: true},
			wantLogs: [][]interface{}{
				{"handling callback request"},
				{"error clearing authorization state", "session-id", sessionID},
			},
		},
		{
			name:              "callback request - fails to set new token response",
			storeCallsToError: map[int]bool{setTokenResponse: true},
			wantLogs: [][]interface{}{
				{"handling callback request"},
				{"saving tokens to session store", "session-id", sessionID},
				{"error saving tokens to session store", "session-id", sessionID},
			},
		},
	}

	for _, tt := range callbackTests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, store.SetAuthorizationState(ctx, sessionID, validAuthState))

			store.errs = tt.storeCallsToError
			t.Cleanup(func() {
				store.errs = nil
				log.clear()
			})

			resp := &envoy.CheckResponse{}
			require.NoError(t, h.Process(ctx, callbackRequest, resp))
			requireSessionErrorResponse(t, resp)
			for _, wantLog := range tt.wantLogs {
				log.requireLog(t, wantLog[0].(string), wantLog[1:]...)
			}
		})

	}
}

func TestOIDCProcessWithFailingJWKSProvider(t *testing.T) {
	require.NoError(t, internal.NewLogSystem(&testLogger{level: telemetry.LevelDebug}, &configv1.Config{LogLevel: "debug"}).(run.PreRunner).PreRun())
	funcJWKSProvider := jwksProviderFunc(func() (jwk.Set, error) {
		return nil, errors.New("test jwks provider error")
	})

	jwkPriv, _ := newKeyPair(t)

	clock := oidc.Clock{}
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
	store := sessions.Get(basicOIDCConfig)
	h, err := NewOIDCHandler(basicOIDCConfig, funcJWKSProvider, sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState))
	require.NoError(t, err)
	log := h.(*oidcHandler).log.(*testLogger)

	idpServer := newServer()
	h.(*oidcHandler).httpClient = idpServer.newHTTPClient()

	ctx := context.Background()

	idpServer.Start()
	t.Cleanup(func() {
		idpServer.Stop()
		require.NoError(t, store.RemoveSession(ctx, sessionID))
		log.clear()
	})

	idpServer.tokensResponse = &tokensResponse{
		IDToken:     newJWT(t, jwkPriv, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
		AccessToken: "access-token",
		TokenType:   "Bearer",
	}
	idpServer.statusCode = http.StatusOK

	// Set the authorization state in the store, so it can be found by the handler
	require.NoError(t, store.SetAuthorizationState(ctx, sessionID, validAuthState))

	resp := &envoy.CheckResponse{}
	err = h.Process(ctx, callbackRequest, resp)
	require.NoError(t, err)

	require.Equal(t, int32(codes.Internal), resp.GetStatus().GetCode())
	requireStandardResponseHeaders(t, resp)
	requireStoredTokens(t, store, sessionID, false)
	log.requireLog(t, "handling callback request")
	log.requireLog(t, "error fetching jwks", "error", errors.New("test jwks provider error"))
}

func TestMatchesCallbackPath(t *testing.T) {
	tests := []struct {
		callback   string
		host, path string
		want       bool
	}{
		{"https://example.com/callback", "example.com", "/callback", true},
		{"http://example.com/callback", "example.com", "/callback", true},
		{"https://example.com/callback", "example.com", "/callback/", false},
		{"http://example.com/callback", "example.com", "/callback/", false},
		{"https://example.com/callback", "example.com", "/callback?query#fragment", true},
		{"http://example.com/callback", "example.com", "/callback?query#fragment", true},
		{"https://example.com:443/callback", "example.com", "/callback", true},
		{"https://example.com:8443/callback", "example.com", "/callback", false},
		{"https://example.com:8443/callback", "example.com:8443", "/callback", true},
		{"http://example.com/callback", "example.com", "/callback", true},
		{"http://example.com:80/callback", "example.com", "/callback", true},
		{"http://example.com:8080/callback", "example.com", "/callback", false},
		{"http://example.com:8080/callback", "example.com:8080", "/callback", true},
	}

	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}

	for _, tt := range tests {
		t.Run(tt.callback, func(t *testing.T) {
			h, err := NewOIDCHandler(&oidcv1.OIDCConfig{CallbackUri: tt.callback}, nil, sessions, oidc.Clock{}, nil)
			require.NoError(t, err)
			got := h.(*oidcHandler).matchesCallbackPath(telemetry.NoopLogger(), &envoy.AttributeContext_HttpRequest{Host: tt.host, Path: tt.path})
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEncodeTokensToHeaders(t *testing.T) {
	const (
		idToken        = "id-token"
		accessToken    = "access-token"
		idTokenB64     = "aWQtdG9rZW4="
		accessTokenB64 = "YWNjZXNzLXRva2Vu"
	)

	tests := []struct {
		name                 string
		config               *oidcv1.OIDCConfig
		idToken, accessToken string
		want                 map[string]string
	}{
		{
			name: "only id token",
			config: &oidcv1.OIDCConfig{
				IdToken: &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: "",
			want: map[string]string{
				"Authorization": "Bearer " + idTokenB64,
			},
		},
		{
			name: "id token and access token",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"Authorization":  "Bearer " + idTokenB64,
				"X-Access-Token": "Bearer " + accessTokenB64,
			},
		},
		{
			name: "not default config",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "X-Id-Token", Preamble: "Other"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token-Other", Preamble: "Other"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"X-Id-Token":           "Other " + idTokenB64,
				"X-Access-Token-Other": "Other " + accessTokenB64,
			},
		},
		{
			name: "config with access token but no access token in response",
			config: &oidcv1.OIDCConfig{
				IdToken:     &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
				AccessToken: &oidcv1.TokenConfig{Header: "X-Access-Token", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: "",
			want: map[string]string{
				"Authorization": "Bearer " + idTokenB64,
			},
		},
		{
			name: "config with no access token but access token in response",
			config: &oidcv1.OIDCConfig{
				IdToken: &oidcv1.TokenConfig{Header: "Authorization", Preamble: "Bearer"},
			},
			idToken: idToken, accessToken: accessToken,
			want: map[string]string{
				"Authorization": "Bearer " + idTokenB64,
			},
		},
	}

	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewOIDCHandler(tt.config, nil, sessions, oidc.Clock{}, nil)
			require.NoError(t, err)

			tokResp := &oidc.TokenResponse{
				IDToken: tt.idToken,
			}
			if tt.accessToken != "" {
				tokResp.AccessToken = tt.accessToken
			}

			got := h.(*oidcHandler).encodeTokensToHeaders(tokResp)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestAreTokensExpired(t *testing.T) {
	jwkPriv, _ := newKeyPair(t)

	tests := []struct {
		name                  string
		config                *oidcv1.OIDCConfig
		idToken               string
		accessTokenExpiration time.Time
		want                  bool
	}{
		{
			name:    "no expiration - only id token",
			config:  &oidcv1.OIDCConfig{},
			idToken: newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			want:    false,
		},
		{
			name:                  "no expiration - id token and access token",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: tomorrow,
			want:                  false,
		},
		{
			name:    "expired - only id token",
			config:  &oidcv1.OIDCConfig{},
			idToken: newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday)),
			want:    true,
		},
		{
			name:                  "expired - id token and access token",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(yesterday)),
			accessTokenExpiration: yesterday,
			want:                  true,
		},
		{
			name:                  "id token not expired, access token expired",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: yesterday,
			want:                  true,
		},
		{
			name:                  "id token not expired, access token expired - but access token not in config",
			config:                &oidcv1.OIDCConfig{},
			idToken:               newJWT(t, jwkPriv, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: yesterday,
			want:                  false,
		},
	}

	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&oidc.Clock{}, time.Hour, time.Hour)}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewOIDCHandler(tt.config, nil, sessions, oidc.Clock{}, nil)
			require.NoError(t, err)

			tokResp := &oidc.TokenResponse{
				IDToken: tt.idToken,
			}
			if !tt.accessTokenExpiration.IsZero() {
				tokResp.AccessToken = "access-token"
				tokResp.AccessTokenExpiresAt = tt.accessTokenExpiration
			}

			got, err := h.(*oidcHandler).areRequiredTokensExpired(tokResp)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestLoadWellKnownConfig(t *testing.T) {
	idpServer := newServer()
	idpServer.Start()
	t.Cleanup(idpServer.Stop)

	require.NoError(t, loadWellKnownConfig(idpServer.newHTTPClient(), dynamicOIDCConfig))
	require.Equal(t, dynamicOIDCConfig.AuthorizationUri, "http://idp-test-server/authorize")
	require.Equal(t, dynamicOIDCConfig.TokenUri, "http://idp-test-server/token")
	require.Equal(t, dynamicOIDCConfig.GetJwksFetcher().GetJwksUri(), "http://idp-test-server/jwks")
}

func TestLoadWellKnownConfigError(t *testing.T) {
	clock := oidc.Clock{}
	sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
	_, err := NewOIDCHandler(dynamicOIDCConfig, oidc.NewJWKSProvider(), sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState))
	require.Error(t, err) // Fail to retrieve the dynamic config since the test server is not running
}

const smallCAPem = `-----BEGIN CERTIFICATE-----
MIIB8TCCAZugAwIBAgIJANZ3fvnlU+1IMA0GCSqGSIb3DQEBCwUAMF4xCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRAwDgYDVQQKDAdUZXRyYXRlMRQw
EgYDVQQLDAtFbmdpbmVlcmluZzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDIx
NjE1MzExOFoXDTI0MDIxNzE1MzExOFowXjELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExEDAOBgNVBAoMB1RldHJhdGUxFDASBgNVBAsMC0VuZ2luZWVy
aW5nMRIwEAYDVQQDDAlsb2NhbGhvc3QwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA
17tRxNJNLZVu2ntW/ehw5BneJFV+o7UmpCipv0zBtMtgJw2Z04fYiipaXgwg/sVL
wnyFgbhd0OgoIEg+ND38iQIDAQABozwwOjASBgNVHRMBAf8ECDAGAQH/AgEBMA4G
A1UdDwEB/wQEAwIC5DAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQEL
BQADQQAnQuyYJ6FbTuwtduT1ZCDcXMqTKcLb4ex3iaowflGubQuCX41yIprFScN4
2P5SpEcFlILZiK6vRzyPmuWEQVVr
-----END CERTIFICATE-----`

func TestNewOIDCHandler(t *testing.T) {

	tests := []struct {
		name    string
		config  *oidcv1.OIDCConfig
		wantErr bool
	}{
		{"empty", &oidcv1.OIDCConfig{}, false},
		{"proxy uri", &oidcv1.OIDCConfig{ProxyUri: "http://proxy"}, false},
		{"trusted CA-invalid", &oidcv1.OIDCConfig{TrustedCertificateAuthority: "<ca pem>"}, true},
		{"trusted CA-valid", &oidcv1.OIDCConfig{TrustedCertificateAuthority: smallCAPem}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := oidc.Clock{}
			sessions := &mockSessionStoreFactory{store: oidc.NewMemoryStore(&clock, time.Hour, time.Hour)}
			_, err := NewOIDCHandler(tt.config, oidc.NewJWKSProvider(), sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

		})
	}
}

func modifyCallbackRequestPath(path string) *envoy.CheckRequest {
	return &envoy.CheckRequest{
		Attributes: &envoy.AttributeContext{
			Request: &envoy.AttributeContext_Request{
				Http: &envoy.AttributeContext_HttpRequest{
					Id:     "request-id",
					Scheme: "https", Host: "localhost:443", Path: path,
					Method: "GET",
					Headers: map[string]string{
						inthttp.HeaderCookie: defaultCookieName + "=test-session-id",
					},
				},
			},
		},
	}
}

const (
	keyID  = "test"
	keyAlg = jwa.RS256
)

func newKeySet(keys ...jwk.Key) jwk.Set {
	jwks := jwk.NewSet()
	for _, k := range keys {
		jwks.Add(k)
	}
	return jwks
}

func newKeyPair(t *testing.T) (jwk.Key, jwk.Key) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	priv, err := jwk.New(rsaKey)
	require.NoError(t, err)

	pub, err := jwk.New(rsaKey.PublicKey)
	require.NoError(t, err)

	err = pub.Set(jwk.KeyIDKey, keyID)
	require.NoError(t, err)
	err = pub.Set(jwk.AlgorithmKey, keyAlg)
	require.NoError(t, err)

	return priv, pub
}

func newJWT(t *testing.T, key jwk.Key, builder *jwt.Builder) string {
	token, err := builder.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, keyAlg, key)
	require.NoError(t, err)
	return string(signed)
}

func requireSessionErrorResponse(t *testing.T, resp *envoy.CheckResponse) {
	require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
	require.Equal(t, "There was an error accessing your session data. Try again later.", resp.GetDeniedResponse().GetBody())
}

func requireStoredTokens(t *testing.T, store oidc.SessionStore, sessionID string, wantExists bool) {
	got, err := store.GetTokenResponse(context.Background(), sessionID)
	require.NoError(t, err)
	if wantExists {
		require.NotNil(t, got)
	} else {
		require.Nil(t, got)
	}
}

func requireStoredState(t *testing.T, store oidc.SessionStore, sessionID string, wantExists bool) {
	got, err := store.GetAuthorizationState(context.Background(), sessionID)
	require.NoError(t, err)
	if wantExists {
		require.NotNil(t, got)
	} else {
		require.Nil(t, got)
	}
}

func requireRedirectResponse(t *testing.T, response *envoy.DeniedHttpResponse, wantRedirectBaseURI string, wantRedirectParams url.Values) {
	var locationHeader string
	for _, header := range response.GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderLocation {
			locationHeader = header.GetHeader().GetValue()
		}
	}

	require.Equal(t, typev3.StatusCode_Found, response.GetStatus().GetCode())
	got, err := url.Parse(locationHeader)
	require.NoError(t, err)

	require.Equal(t, wantRedirectBaseURI, got.Scheme+"://"+got.Host+got.Path)

	gotParams := got.Query()
	for k, v := range wantRedirectParams {
		require.Equal(t, v, gotParams[k])
	}
	require.Len(t, gotParams, len(wantRedirectParams))
}

func requireCookie(t *testing.T, response *envoy.DeniedHttpResponse) {
	var cookieHeader string
	for _, header := range response.GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderSetCookie {
			cookieHeader = header.GetHeader().GetValue()
		}
	}
	require.Equal(t, "__Host-authservice-session-id-cookie=new-session-id; HttpOnly; Secure; SameSite=Lax; Path=/", cookieHeader)
}

func requireTokensInResponse(t *testing.T, resp *envoy.OkHttpResponse, cfg *oidcv1.OIDCConfig, idToken, accessToken string) {
	var (
		gotIDToken, gotAccessToken   string
		wantIDToken, wantAccessToken string
	)

	wantIDToken = cfg.GetIdToken().GetPreamble() + " " + base64.URLEncoding.EncodeToString([]byte(idToken))
	if cfg.GetAccessToken() != nil {
		wantAccessToken = cfg.GetAccessToken().GetPreamble() + " " + base64.URLEncoding.EncodeToString([]byte(accessToken))
	}

	for _, header := range resp.GetHeaders() {
		if header.GetHeader().GetKey() == cfg.GetIdToken().GetHeader() {
			gotIDToken = header.GetHeader().GetValue()
		}
		if header.GetHeader().GetKey() == cfg.GetAccessToken().GetHeader() {
			gotAccessToken = header.GetHeader().GetValue()
		}
	}

	require.Equal(t, wantIDToken, gotIDToken)
	if cfg.GetAccessToken() != nil {
		require.Equal(t, wantAccessToken, gotAccessToken)
	} else {
		require.Empty(t, gotAccessToken)
	}
}

func requireStandardResponseHeaders(t *testing.T, resp *envoy.CheckResponse) {
	for _, header := range resp.GetDeniedResponse().GetHeaders() {
		if header.GetHeader().GetKey() == inthttp.HeaderCacheControl {
			require.EqualValues(t, inthttp.HeaderCacheControlNoCache, header.GetHeader().GetValue())
		}
		if header.GetHeader().GetKey() == inthttp.HeaderPragma {
			require.EqualValues(t, inthttp.HeaderPragmaNoCache, header.GetHeader().GetValue())
		}
	}
}

// idpServer is a mock IDP server that can be used to test the OIDC handler.
// It listens on a bufconn.Listener and provides a http.Client that can be used to make requests to it.
// It returns a predefined response when the /token endpoint is called, that can be set using the tokensResponse field.
type idpServer struct {
	server         *http.Server
	listener       *bufconn.Listener
	tokensResponse *tokensResponse
	statusCode     int
}

func newServer() *idpServer {
	s := &http.Server{}
	idpServer := &idpServer{server: s, listener: bufconn.Listen(1024)}

	handler := http.NewServeMux()
	handler.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(idpServer.statusCode)

		if idpServer.statusCode == http.StatusOK && idpServer.tokensResponse != nil {
			err := json.NewEncoder(w).Encode(idpServer.tokensResponse)
			if err != nil {
				http.Error(w, fmt.Errorf("cannot json encode id_token: %w", err).Error(), http.StatusInternalServerError)
			}
		}
	})
	handler.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(wellKnownURIs))
	})
	s.Handler = handler
	return idpServer
}

// Start starts the server in a goroutine.
func (s *idpServer) Start() {
	go func() { _ = s.server.Serve(s.listener) }()
}

// Stop stops the server.
func (s *idpServer) Stop() {
	_ = s.listener.Close()
}

// newHTTPClient returns a new http.Client that can be used to make requests to the server via the bufconn.Listener.
func (s *idpServer) newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return s.listener.DialContext(ctx)
			},
		},
	}
}

const (
	setTokenResponse = iota
	getTokenResponse
	setAuthorizationState
	getAuthorizationState
	clearAuthorizationState
	removeSession
	removeAllExpired
)

var (
	_ oidc.SessionStore = &storeMock{}

	errStore = errors.New("store error")
)

// storeMock is a mock implementation of oidc.SessionStore that allows to configure when a method must fail with an error.
type storeMock struct {
	delegate oidc.SessionStore
	errs     map[int]bool
}

// SetTokenResponse Implements oidc.SessionStore.
func (s *storeMock) SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *oidc.TokenResponse) error {
	if s.errs[setTokenResponse] {
		return errStore
	}
	return s.delegate.SetTokenResponse(ctx, sessionID, tokenResponse)
}

// GetTokenResponse Implements oidc.SessionStore.
func (s *storeMock) GetTokenResponse(ctx context.Context, sessionID string) (*oidc.TokenResponse, error) {
	if s.errs[getTokenResponse] {
		return nil, errStore
	}
	return s.delegate.GetTokenResponse(ctx, sessionID)
}

// SetAuthorizationState Implements oidc.SessionStore.
func (s *storeMock) SetAuthorizationState(ctx context.Context, sessionID string, authorizationState *oidc.AuthorizationState) error {
	if s.errs[setAuthorizationState] {
		return errStore
	}
	return s.delegate.SetAuthorizationState(ctx, sessionID, authorizationState)
}

// GetAuthorizationState Implements oidc.SessionStore.
func (s *storeMock) GetAuthorizationState(ctx context.Context, sessionID string) (*oidc.AuthorizationState, error) {
	if s.errs[getAuthorizationState] {
		return nil, errStore
	}
	return s.delegate.GetAuthorizationState(ctx, sessionID)
}

// ClearAuthorizationState Implements oidc.SessionStore.
func (s *storeMock) ClearAuthorizationState(ctx context.Context, sessionID string) error {
	if s.errs[clearAuthorizationState] {
		return errStore
	}
	return s.delegate.ClearAuthorizationState(ctx, sessionID)
}

// RemoveSession Implements oidc.SessionStore.
func (s *storeMock) RemoveSession(ctx context.Context, sessionID string) error {
	if s.errs[removeSession] {
		return errStore
	}
	return s.delegate.RemoveSession(ctx, sessionID)
}

// RemoveAllExpired Implements oidc.SessionStore.
func (s *storeMock) RemoveAllExpired(ctx context.Context) error {
	if s.errs[removeAllExpired] {
		return errStore
	}
	return s.delegate.RemoveAllExpired(ctx)
}

var _ oidc.SessionStoreFactory = &mockSessionStoreFactory{}

// mockSessionStoreFactory is a mock implementation of oidc.SessionStoreFactory that returns a predefined store.
type mockSessionStoreFactory struct {
	store oidc.SessionStore
}

func (m mockSessionStoreFactory) Get(_ *oidcv1.OIDCConfig) oidc.SessionStore {
	return m.store
}

var _ oidc.JWKSProvider = jwksProviderFunc(nil)

type jwksProviderFunc func() (jwk.Set, error)

func (j jwksProviderFunc) Get(context.Context, *oidcv1.OIDCConfig) (jwk.Set, error) {
	return j()
}

var _ telemetry.Logger = &testLogger{}

// testLogger is a mock implementation of telemetry.Logger that saves the messages logged and the key-value pairs.
// Initializing any log system with a new instances of this is enough to test the logs.
// It is strongly recommended to call the clear method in each test cleanup to ensure the expected logs are
// produced in the current iteration.
type testLogger struct {
	level telemetry.Level

	// messages hold the messages logged, indexed by the msg field and saving the key-value pairs.
	messages map[string]map[string]interface{}
	m        sync.Mutex

	// loggers holds the loggers created by the Clone, With and Context methods.
	loggers []*testLogger

	// extraKVPairs holds the key-value pairs that are added to the loggers created by the With and Context methods.
	extraKVPairs []interface{}
}

// message saves the message and the key-value pairs in the messages field.
func (t *testLogger) message(msg string, keyValuePairs ...interface{}) {
	t.m.Lock()
	defer t.m.Unlock()
	if t.messages == nil {
		t.messages = make(map[string]map[string]interface{})
	}
	if _, ok := t.messages[msg]; !ok {
		t.messages[msg] = make(map[string]interface{})
	}
	kvPairs := append(keyValuePairs, t.extraKVPairs...)
	for i := 0; i < len(kvPairs); i += 2 {
		t.messages[msg][kvPairs[i].(string)] = kvPairs[i+1]
	}
}

// Debug Implements telemetry.Logger.
func (t *testLogger) Debug(msg string, keyValuePairs ...interface{}) {
	if t.level < telemetry.LevelDebug {
		return
	}
	kv := append(keyValuePairs, "level", "debug")
	t.message(msg, kv...)
}

// Info Implements telemetry.Logger.
func (t *testLogger) Info(msg string, keyValuePairs ...interface{}) {
	if t.level < telemetry.LevelInfo {
		return
	}
	kv := append(keyValuePairs, "level", "info")
	t.message(msg, kv...)
}

// Error Implements telemetry.Logger.
func (t *testLogger) Error(msg string, err error, keyValuePairs ...interface{}) {
	if t.level < telemetry.LevelError {
		return
	}
	kv := append(keyValuePairs, "level", "error", "error", err)
	t.message(msg, kv...)
}

// SetLevel Implements telemetry.Logger.
func (t *testLogger) SetLevel(lvl telemetry.Level) {
	t.m.Lock()
	defer t.m.Unlock()
	t.level = lvl
}

// Level Implements telemetry.Logger.
func (t *testLogger) Level() telemetry.Level {
	t.m.Lock()
	defer t.m.Unlock()
	return t.level
}

// With Implements telemetry.Logger.
// generates a new instance inheriting the key-value pairs and save this new instance to the parent one.
func (t *testLogger) With(keyValuePairs ...interface{}) telemetry.Logger {
	t.m.Lock()
	defer t.m.Unlock()
	n := &testLogger{
		level:        t.level,
		extraKVPairs: append(t.extraKVPairs, keyValuePairs...),
	}
	t.loggers = append(t.loggers, n)
	return n
}

// Context Implements telemetry.Logger.
// generates a new instance inheriting the key-value pairs  and save this new instance to the parent one.
func (t *testLogger) Context(ctx context.Context) telemetry.Logger {
	t.m.Lock()
	defer t.m.Unlock()
	n := &testLogger{
		level:        t.level,
		extraKVPairs: append(t.extraKVPairs, telemetry.KeyValuesFromContext(ctx)...),
	}
	t.loggers = append(t.loggers, n)
	return n
}

// Metric Implements telemetry.Logger.
// not implemented & not used.
func (t *testLogger) Metric(telemetry.Metric) telemetry.Logger {
	panic("implement me")
}

// Clone Implements telemetry.Logger.
// generates a new instance inheriting the key-value pairs and save this new instance to the parent one.
func (t *testLogger) Clone() telemetry.Logger {
	t.m.Lock()
	defer t.m.Unlock()

	n := &testLogger{
		level:        t.level,
		extraKVPairs: append(make([]interface{}, 0, len(t.extraKVPairs)), t.extraKVPairs...),
	}
	t.loggers = append(t.loggers, n)
	return n
}

// getAllLoggers recursively gets all the children loggers.
func (t *testLogger) getAllLoggers() []*testLogger {
	t.m.Lock()
	defer t.m.Unlock()

	loggers := make([]*testLogger, 0)
	for _, l := range t.loggers {
		loggers = append(loggers, l)
		loggers = append(loggers, l.getAllLoggers()...)
	}
	return loggers
}

// requireLog checks if the message and the key-value pairs are present in the loggers.
func (t *testLogger) requireLog(tt *testing.T, msg string, keyValuePairs ...interface{}) {
	tt.Helper()
	loggers := t.getAllLoggers()

	t.m.Lock()
	defer t.m.Unlock()

	var (
		gotKVPairs map[string]interface{}
		ok         bool
	)

	for _, l := range loggers {
		if gotKVPairs, ok = l.messages[msg]; ok {
			break
		}
	}
	require.True(tt, ok, "message not found: %s", msg)

	for i := 0; i < len(keyValuePairs); i += 2 {
		expKey := keyValuePairs[i].(string)
		expValue := keyValuePairs[i+1]
		gotValue, ok := gotKVPairs[expKey]
		require.True(tt, ok, "key not found: %s", expKey)
		require.Equal(tt, expValue, gotValue)
	}
}

// clear clears the messages and the loggers.
func (t *testLogger) clear() {
	t.m.Lock()
	defer t.m.Unlock()

	t.loggers = nil
}
