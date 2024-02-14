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
		IDToken:              newToken(),
		AccessToken:          newToken(),
		AccessTokenExpiresAt: time.Now().Add(30 * time.Minute),
		RefreshToken:         newToken(),
	}
	require.NoError(t, store.SetTokenResponse(ctx, "s1", tr))

	// Verify we can retrieve the token
	got, err := store.GetTokenResponse(ctx, "s1")
	require.NoError(t, err)
	// The testify library doesn't properly compare times, so we need to do it manually
	// then set the times in the returned object so that we can compare the rest of the
	// fields normally
	require.True(t, tr.AccessTokenExpiresAt.Equal(got.AccessTokenExpiresAt))
	got.AccessTokenExpiresAt = tr.AccessTokenExpiresAt
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

func TestRedisPingError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.SetError("ping error")

	_, err := NewRedisStore(&Clock{}, client, 0, 1*time.Minute)
	require.EqualError(t, err, "ping error")
}

func TestRefreshExpiration(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := NewRedisStore(&Clock{}, client, 0, 0)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("delete session if no time added", func(t *testing.T) {
		require.NoError(t, client.HSet(ctx, "s1", keyAccessToken, "").Err())
		err := store.(*redisStore).refreshExpiration(ctx, "s1", time.Time{})
		require.ErrorIs(t, err, ErrRedis)
		require.Equal(t, redis.Nil, client.Get(ctx, "s1").Err())
	})

	t.Run("no expiration set if no timeouts", func(t *testing.T) {
		require.NoError(t, client.HSet(ctx, "s1", keyTimeAdded, time.Now()).Err())
		require.NoError(t, store.(*redisStore).refreshExpiration(ctx, "s1", time.Time{}))

		res, err := client.TTL(ctx, "s1").Result()
		require.NoError(t, err)
		require.Equal(t, time.Duration(-1), res)
	})

	// TODO(nacx): Expiration is updated
}
