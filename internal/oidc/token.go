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
	"github.com/lestrrat-go/jwx/jwt"
)

// TokenResponse contains information about the tokens returned by the Identity Provider.
type TokenResponse struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

func (t *TokenResponse) GetIDToken() (jwt.Token, error)      { return parse(t.IDToken) }
func (t *TokenResponse) GetAccessToken() (jwt.Token, error)  { return parse(t.AccessToken) }
func (t *TokenResponse) GetRefreshToken() (jwt.Token, error) { return parse(t.RefreshToken) }

func parse(token string) (jwt.Token, error) {
	return jwt.Parse([]byte(token), jwt.WithValidate(false))
}
