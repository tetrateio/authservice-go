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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/log"
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

	yesterday = time.Now().Add(-24 * time.Hour)
	tomorrow  = time.Now().Add(24 * time.Hour)

	sessionID    = "test-session-id"
	newSessionID = "new-session-id"
	newNonce     = "new-nonce"
	newState     = "new-state"
)

func TestOIDCProcess(t *testing.T) {
	require.NoError(t, internal.NewLogSystem(log.New(), &configv1.Config{LogLevel: "debug"}).(run.PreRunner).PreRun())

	cfg := &oidcv1.OIDCConfig{
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

	wantRedirectParams := url.Values{}
	wantRedirectParams.Add("response_type", "code")
	wantRedirectParams.Add("client_id", "test-client-id")
	wantRedirectParams.Add("redirect_uri", "https://localhost:443/callback")
	wantRedirectParams.Add("scope", "openid email")
	wantRedirectParams.Add("state", newState)
	wantRedirectParams.Add("nonce", newNonce)
	wantRedirectBaseURI := "http://idp-test-server/auth"

	clock := oidc.Clock{}
	sessions := inMemSessionFactory(t)
	store := sessions.Get(cfg)
	h, err := NewOIDCHandler(cfg, oidc.NewJWKSProvider(), sessions, clock, oidc.NewStaticGenerator(newSessionID, newNonce, newState))
	require.NoError(t, err)

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
			},
		},
		{
			name: "request with an existing sessionID expired",
			req:  withSessionHeader,
			storedTokenResponse: &oidc.TokenResponse{
				IDToken:              newJWT(t, jwt.NewBuilder().Expiration(yesterday)),
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
			},
		},
		{
			name: "request with an existing sessionID not expired",
			req:  withSessionHeader,
			storedTokenResponse: &oidc.TokenResponse{
				IDToken:              newJWT(t, jwt.NewBuilder().Expiration(tomorrow)),
				AccessToken:          "access-token",
				AccessTokenExpiresAt: tomorrow,
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
				require.NotNil(t, resp.GetOkResponse())
				requireTokensInResponse(t, resp.GetOkResponse(), cfg, newJWT(t, jwt.NewBuilder().Expiration(tomorrow)), "access-token")
				// The sessionID should not have been changed
				requireStoredTokens(t, store, sessionID, true)
				requireStoredState(t, store, newSessionID, false)
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
	}

	for _, tt := range requestToAppTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				require.NoError(t, store.RemoveSession(ctx, sessionID))
				require.NoError(t, store.RemoveSession(ctx, newSessionID))
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

	validAuthState := &oidc.AuthorizationState{
		Nonce:        newNonce,
		State:        newState,
		RequestedURL: "https://localhost:443/final-app",
	}

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
				IDToken:     newJWT(t, jwt.NewBuilder().Audience([]string{"test-client-id"}).Claim("nonce", newNonce)),
				AccessToken: "access-token",
				TokenType:   "Bearer",
			},
			responseVerify: func(t *testing.T, resp *envoy.CheckResponse) {
				require.Equal(t, int32(codes.Unauthenticated), resp.GetStatus().GetCode())
				requireStandardResponseHeaders(t, resp)
				requireRedirectResponse(t, resp.GetDeniedResponse(), "https://localhost:443/final-app", nil)
				requireStoredTokens(t, store, sessionID, true)
				requireStoredTokens(t, store, newSessionID, false)
			},
		},
		{
			name: "request is invalid, query parameters are missing",
			req:  modifyCallbackRequestPaht("/callback?"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "request is invalid, query has invalid format",
			req:  modifyCallbackRequestPaht("/callback?invalid;format"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "request is invalid, state is missing",
			req:  modifyCallbackRequestPaht("/callback?code=auth-code"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name: "request is invalid, code is missing",
			req:  modifyCallbackRequestPaht("/callback?state=new-state"),
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
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
			},
		},
		{
			name: "session state stored does not match the request",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        newNonce,
				State:        "non-matching-state",
				RequestedURL: "https://localhost:443/final-app",
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
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
			},
		},
		{
			name: "session nonce stored does idp returned nonce",
			req:  callbackRequest,
			storedAuthState: &oidc.AuthorizationState{
				Nonce:        "old-nonce",
				State:        newState,
				RequestedURL: "https://localhost:443/final-app",
			},
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, jwt.NewBuilder().Claim("nonce", "non-matching-nonce")),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned empty audience",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, jwt.NewBuilder().Audience(nil)),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned non-matching audience",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken: newJWT(t, jwt.NewBuilder().Audience([]string{"non-matching-audience"})),
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned non-bearer token type",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:   newJWT(t, jwt.NewBuilder().Audience([]string{"test-client-id"})),
				TokenType: "not-bearer",
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp returned invalid expires_in for access token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:   newJWT(t, jwt.NewBuilder().Audience([]string{"test-client-id"})),
				TokenType: "Bearer",
				ExpiresIn: -1,
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
		{
			name:            "idp didn't return access token",
			req:             callbackRequest,
			storedAuthState: validAuthState,
			mockTokensResponse: &tokensResponse{
				IDToken:   newJWT(t, jwt.NewBuilder().Audience([]string{"test-client-id"})),
				TokenType: "Bearer",
				ExpiresIn: 3600,
			},
			responseVerify: func(t *testing.T, response *envoy.CheckResponse) {
				require.Equal(t, int32(codes.InvalidArgument), response.GetStatus().GetCode())
				requireStandardResponseHeaders(t, response)
				requireStoredTokens(t, store, sessionID, false)
			},
		},
	}

	for _, tt := range callbackTests {
		t.Run("request matches callback: "+tt.name, func(t *testing.T) {
			idpServer.Start()
			t.Cleanup(func() {
				idpServer.Stop()
				require.NoError(t, store.RemoveSession(ctx, sessionID))
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
func modifyCallbackRequestPaht(path string) *envoy.CheckRequest {
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

func newJWT(t *testing.T, builder *jwt.Builder) string {
	token, err := builder.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwa.HS256, []byte("key"))
	require.NoError(t, err)
	return string(signed)
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
	s.Handler = handler
	return idpServer
}

func (s *idpServer) Start() {
	go func() { _ = s.server.Serve(s.listener) }()
}

func (s *idpServer) Stop() {
	_ = s.listener.Close()
}

func (s *idpServer) newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return s.listener.DialContext(ctx)
			},
		},
	}
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

	sessions := inMemSessionFactory(t)

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

	sessions := inMemSessionFactory(t)

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
			idToken: newJWT(t, jwt.NewBuilder().Expiration(tomorrow)),
			want:    false,
		},
		{
			name:                  "no expiration - id token and access token",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: tomorrow,
			want:                  false,
		},
		{
			name:    "expired - only id token",
			config:  &oidcv1.OIDCConfig{},
			idToken: newJWT(t, jwt.NewBuilder().Expiration(yesterday)),
			want:    true,
		},
		{
			name:                  "expired - id token and access token",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwt.NewBuilder().Expiration(yesterday)),
			accessTokenExpiration: yesterday,
			want:                  true,
		},
		{
			name:                  "id token not expired, access token expired",
			config:                &oidcv1.OIDCConfig{AccessToken: &oidcv1.TokenConfig{}},
			idToken:               newJWT(t, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: yesterday,
			want:                  true,
		},
		{
			name:                  "id token not expired, access token expired - but access token not in config",
			config:                &oidcv1.OIDCConfig{},
			idToken:               newJWT(t, jwt.NewBuilder().Expiration(tomorrow)),
			accessTokenExpiration: yesterday,
			want:                  false,
		},
	}

	sessions := inMemSessionFactory(t)

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

func inMemSessionFactory(t *testing.T) *oidc.SessionStoreFactory {
	sessions := &oidc.SessionStoreFactory{
		Config: &configv1.Config{
			Chains: []*configv1.FilterChain{
				{
					Filters: []*configv1.Filter{
						{
							Type: &configv1.Filter_Oidc{Oidc: &oidcv1.OIDCConfig{}},
						},
					},
				},
			},
		},
	}
	require.NoError(t, sessions.PreRun())
	return sessions
}
