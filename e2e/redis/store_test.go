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

package mock

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/tetrateio/authservice-go/internal/oidc"
)

const redisURL = "redis://localhost:6379"

func TestRedisTokenResponse(t *testing.T) {
	opts, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	client := redis.NewClient(opts)

	store, err := oidc.NewRedisStore(&oidc.Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	ctx := context.Background()

	tr, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	require.Nil(t, tr)

	// Create a session and verify it's added and accessed time
	tr = &oidc.TokenResponse{
		IDToken:     newToken(),
		AccessToken: newToken(),
	}
	require.NoError(t, store.SetTokenResponse(ctx, "s1", tr))

	// Verify we can retrieve the token
	got, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	require.Equal(t, tr, got)

	// Verify that the token TTL has been set
	ttl := client.TTL(ctx, "s1").Val()
	require.Greater(t, ttl, time.Duration(0))
}

func newToken() string {
	token, _ := jwt.NewBuilder().
		Issuer("authservice").
		Subject("user").
		Expiration(time.Now().Add(time.Hour)).
		Build()
	signed, _ := jwt.Sign(token, jwa.HS256, []byte("key"))
	return string(signed)
}
