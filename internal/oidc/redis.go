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

	"github.com/redis/go-redis/v9"
	"github.com/tetratelabs/telemetry"

	"github.com/tetrateio/authservice-go/internal"
)

var (
	_ SessionStore = (*redisStore)(nil)

	ErrRedis = errors.New("redis error")
)

const (
	keyIDToken      = "id_token"
	keyAccessToken  = "access_token"
	keyRefreshToken = "refresh_token"
	keyState        = "state"
	keyNonce        = "nonce"
	keyRequestedURL = "requested_url"
	keyTimeAdded    = "time_added"
)

var (
	tokenResponseKeys = []string{keyIDToken, keyAccessToken, keyRefreshToken, keyTimeAdded}
	// authorizationStateKeys = []string{keyState, keyNonce, keyRequestedURL, keyTimeAdded}
)

// redisStore is an in-memory implementation of the SessionStore interface that stores
// the session data in a given Redis server.
type redisStore struct {
	//TODO(nacx): Remove this interface embedding when the interface is fully implemented
	SessionStore
	log                    telemetry.Logger
	clock                  *Clock
	client                 redis.Cmdable
	absoluteSessionTimeout time.Duration
	idleSessionTimeout     time.Duration
}

// NewRedisStore creates a new SessionStore that stores the session data in a given Redis server.
func NewRedisStore(clock *Clock, client redis.Cmdable, absoluteSessionTimeout, idleSessionTimeout time.Duration) (SessionStore, error) {
	if err := client.Ping(context.TODO()).Err(); err != nil {
		return nil, err
	}

	return &redisStore{
		log:                    internal.Logger(internal.Session).With("type", "redis"),
		clock:                  clock,
		client:                 client,
		absoluteSessionTimeout: absoluteSessionTimeout,
		idleSessionTimeout:     idleSessionTimeout,
	}, nil
}

func (r *redisStore) SetTokenResponse(ctx context.Context, sessionID string, tokenResponse *TokenResponse) error {
	if err := r.client.HSet(ctx, sessionID, keyIDToken, tokenResponse.IDToken).Err(); err != nil {
		return err
	}

	var keysToDelete []string

	if tokenResponse.AccessToken != "" {
		if err := r.client.HSet(ctx, sessionID, keyAccessToken, tokenResponse.AccessToken).Err(); err != nil {
			return err
		}
	} else {
		keysToDelete = append(keysToDelete, keyAccessToken)
	}

	if tokenResponse.RefreshToken != "" {
		if err := r.client.HSet(ctx, sessionID, keyRefreshToken, tokenResponse.RefreshToken).Err(); err != nil {
			return err
		}
	} else {
		keysToDelete = append(keysToDelete, keyRefreshToken)
	}

	if len(keysToDelete) > 0 {
		if err := r.client.HDel(ctx, sessionID, keysToDelete...).Err(); err != nil {
			return err
		}
	}

	now := r.clock.Now()
	if err := r.client.HSetNX(ctx, sessionID, keyTimeAdded, now).Err(); err != nil {
		return err
	}

	return r.refreshExpiration(ctx, sessionID, now)
}

func (r *redisStore) GetTokenResponse(ctx context.Context, sessionID string) (*TokenResponse, error) {
	log := r.log.Context(ctx)

	res := r.client.HMGet(ctx, sessionID, tokenResponseKeys...)
	if res.Err() != nil {
		return nil, res.Err()
	}

	var token redisToken
	if err := res.Scan(&token); err != nil {
		return nil, err
	}

	if token.IDToken == "" {
		log.Debug("id token not found", "session_id", sessionID)
		return nil, nil
	}

	tokenResponse := token.TokenResponse()
	if _, err := tokenResponse.GetIDToken(); err != nil {
		log.Error("failed to parse id token", err, "session_id", sessionID, "token", token)
		return nil, nil
	}

	if err := r.refreshExpiration(ctx, sessionID, token.TimeAdded); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}

func (r *redisStore) refreshExpiration(ctx context.Context, sessionID string, timeAdded time.Time) error {
	if timeAdded.IsZero() {
		timeAdded, _ = r.client.HGet(ctx, sessionID, keyTimeAdded).Time()
	}

	if timeAdded.IsZero() {
		if err := r.client.Del(ctx, sessionID).Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: session did not contain creation timestamp", ErrRedis)
	}

	if r.absoluteSessionTimeout == 0 && r.idleSessionTimeout == 0 {
		return nil
	}

	var (
		now              = r.clock.Now()
		absoluteExpireAt = timeAdded.Add(r.absoluteSessionTimeout)
		idleExpireAt     = now.Add(r.idleSessionTimeout)
		expireAt         time.Time
	)

	if r.absoluteSessionTimeout == 0 {
		expireAt = idleExpireAt
	} else if r.idleSessionTimeout == 0 {
		expireAt = absoluteExpireAt
	} else {
		expireAt = absoluteExpireAt
		if idleExpireAt.Before(expireAt) {
			expireAt = idleExpireAt
		}
	}

	return r.client.ExpireAt(ctx, sessionID, expireAt).Err()
}

type redisToken struct {
	IDToken      string    `redis:"id_token"`
	AccessToken  string    `redis:"access_token"`
	RefreshToken string    `redis:"refresh_token"`
	TimeAdded    time.Time `redis:"time_added"`
}

func (r redisToken) TokenResponse() TokenResponse {
	return TokenResponse{
		IDToken:      r.IDToken,
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
	}
}
