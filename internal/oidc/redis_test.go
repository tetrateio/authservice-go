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
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRedisTokenResponse(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.NoError(t, err)

	ctx := context.Background()

	tr, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	require.Nil(t, tr)

	// Create a session and verify it's added and accessed time
	tr = &TokenResponse{
		IDToken:      newToken(),
		AccessToken:  newToken(),
		RefreshToken: newToken(),
	}
	require.NoError(t, store.SetTokenResponse(ctx, "s1", tr))

	// Verify we can retrieve the token
	got, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	require.Equal(t, tr, got)

	// Verify that the token TTL has been set
	added, _ := client.HGet(ctx, "s1", keyTimeAdded).Time()
	ttl := client.TTL(ctx, "s1").Val()
	require.Greater(t, added.Unix(), int64(0))
	require.Greater(t, ttl, time.Duration(0))

	// Check keys are deleted
	tr.AccessToken = ""
	tr.RefreshToken = ""
	require.NoError(t, store.SetTokenResponse(ctx, "s1", tr))

	var rt redisToken
	vals := client.HMGet(ctx, "s1", keyAccessToken, keyRefreshToken)
	require.NoError(t, vals.Scan(&rt))
	require.Empty(t, rt.AccessToken)
	require.Empty(t, rt.RefreshToken)
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
