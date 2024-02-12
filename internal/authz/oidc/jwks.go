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
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tetratelabs/telemetry"

	"github.com/tetrateio/authservice-go/internal"
)

// JWKSProvider is an interface for providing JWKS documents.
type JWKSProvider interface {
	// Get the configured JWKS document.
	Get(context.Context) (jwk.Set, error)
}

var (
	_ JWKSProvider = (*staticJWKSProvider)(nil)
	_ JWKSProvider = (*dynamicJWKSProvider)(nil)

	// ErrJWKSParse is returned when the JWKS document cannot be parsed.
	ErrJWKSParse = errors.New("error parsing JWKS document")
	// ErrJWKSFetch is returned when the JWKS document cannot be fetched.
	ErrJWKSFetch = errors.New("error fetching JWKS document")
)

// staticJWKSProvider is a JWKSProvider that returns a static JWKS document.
type staticJWKSProvider struct {
	log  telemetry.Logger
	jwks jwk.Set
}

// NewStaticJWKSProvider returns a new JWKSProvider that returns the given raw JWKS document.
func NewStaticJWKSProvider(raw string) (JWKSProvider, error) {
	jwks, err := jwk.Parse([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSParse, err)
	}

	return &staticJWKSProvider{
		log:  internal.Logger(internal.JWKS),
		jwks: jwks,
	}, nil
}

func (s *staticJWKSProvider) Get(_ context.Context) (jwk.Set, error) {
	return s.jwks, nil
}

// dynamicJWKSProvider is a JWKSProvider that returns a JWKS document from a URL and
// updates it asynchronously on a regular interval.
type dynamicJWKSProvider struct {
	log             telemetry.Logger
	jwksURL         string
	refreshInterval time.Duration
	// cache of JWKS documents internally cached by the JWKS URL.
	cache *jwk.AutoRefresh
}

// NewDynamicJWKSProvider returns a new JWKSProvider that returns the JWKS document from the given URL.
func NewDynamicJWKSProvider(ctx context.Context, jwksURL string, refreshInterval time.Duration) JWKSProvider {
	log := internal.Logger(internal.JWKS)

	ch := make(chan jwk.AutoRefreshError)
	autoRefresh := jwk.NewAutoRefresh(ctx)
	autoRefresh.ErrorSink(ch)
	autoRefresh.Configure(jwksURL, jwk.WithRefreshInterval(refreshInterval))

	go func(ctx context.Context) {
		for {
			select {
			case err := <-ch:
				log.Debug("jwks auto refresh error", "error", err)
			case <-ctx.Done():
				return
			}
		}
	}(ctx)

	return &dynamicJWKSProvider{
		log:             log,
		jwksURL:         jwksURL,
		refreshInterval: refreshInterval,
		cache:           autoRefresh,
	}
}

// Get the JWKS document from the configured URL.
// The JWKS document is cached and auto-updated at the configured interval.
func (d *dynamicJWKSProvider) Get(ctx context.Context) (jwk.Set, error) {
	jwks, err := d.cache.Fetch(ctx, d.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	return jwks, nil
}
