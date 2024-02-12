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
	"time"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"

	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
	"github.com/tetrateio/authservice-go/internal/authz/oidc"
)

var _ Handler = (*oidcHandler)(nil)

// oidc handler is an implementation of the Handler interface that implements
// the OpenID connect protocol.
type oidcHandler struct {
	log    telemetry.Logger
	config *oidcv1.OIDCConfig
	store  oidc.SessionStore
	jwks   oidc.JWKSProvider
}

// NewOIDCHandler creates a new OIDC implementation of the Handler interface.
func NewOIDCHandler(cfg *oidcv1.OIDCConfig) (Handler, error) {
	// TODO(nacx): Read the redis store config to configure the redi store
	store := oidc.NewMemoryStore(
		oidc.Clock{},
		time.Duration(cfg.AbsoluteSessionTimeout),
		time.Duration(cfg.IdleSessionTimeout),
	)

	var (
		jwks oidc.JWKSProvider
		err  error
	)
	if cfg.GetJwksFetcher() != nil {
		jwks = oidc.NewDynamicJWKSProvider(
			context.TODO(),
			cfg.GetJwksFetcher().GetJwksUri(),
			time.Duration(cfg.GetJwksFetcher().GetPeriodicFetchIntervalSec())*time.Second,
		)
	} else {
		if jwks, err = oidc.NewStaticJWKSProvider(cfg.GetJwks()); err != nil {
			return nil, err
		}
	}

	return &oidcHandler{
		log:    internal.Logger(internal.Authz).With("type", "oidc"),
		config: cfg,
		store:  store,
		jwks:   jwks,
	}, nil
}

// Process a CheckRequest and populate a CheckResponse according to the mockHandler configuration.
func (o *oidcHandler) Process(_ context.Context, _ *envoy.CheckRequest, _ *envoy.CheckResponse) error {
	return nil
}
