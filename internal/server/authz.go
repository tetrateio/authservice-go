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

package server

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tetratelabs/telemetry"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	mockv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/mock"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
	"github.com/tetrateio/authservice-go/internal"
)

var (
	// allow a request
	allow = &envoy.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.OK),
			Message: "",
		},
	}

	// deny a request with the given code and message
	deny = func(code codes.Code, message string) *envoy.CheckResponse {
		return &envoy.CheckResponse{
			Status: &status.Status{
				Code:    int32(code),
				Message: message,
			},
		}
	}
)

// ExtAuthZFilter is an implementation of the Envoy AuthZ filter.
type ExtAuthZFilter struct {
	log telemetry.Logger
	cfg *configv1.Config
}

// NewExtAuthZFilter creates a new ExtAuthZFilter.
func NewExtAuthZFilter(cfg *configv1.Config) *ExtAuthZFilter {
	return &ExtAuthZFilter{
		log: internal.Logger(internal.Authz),
		cfg: cfg,
	}
}

// Register the ExtAuthZFilter with the given gRPC server.
func (e *ExtAuthZFilter) Register(server *grpc.Server) {
	envoy.RegisterAuthorizationServer(server, e)
}

// Check is the implementation of the Envoy AuthorizationServer interface.
func (e *ExtAuthZFilter) Check(ctx context.Context, req *envoy.CheckRequest) (response *envoy.CheckResponse, err error) {
	// If there are no trigger rules, allow the request with no check executions.
	// TriggerRules are used to determine which request should be checked by the filter and which don't.
	log := e.log.Context(ctx)
	if !mustTriggerCheck(log, e.cfg.TriggerRules, req) {
		log.Debug(fmt.Sprintf("no matching trigger rule, so allowing request to proceed without any authservice functionality %s://%s%s",
			req.GetAttributes().GetRequest().GetHttp().GetScheme(),
			req.GetAttributes().GetRequest().GetHttp().GetHost(),
			req.GetAttributes().GetRequest().GetHttp().GetPath()))
		return allow, nil
	}

	for _, c := range e.cfg.Chains {
		match := matches(c.Match, req)

		log = log.With("chain", c.Name)
		log.Debug("evaluate filter chain", "match", match)

		if !match {
			continue
		}

		// Inside a filter chain, all filters must match
		for i, f := range c.Filters {
			var (
				ok  bool
				err error
			)

			switch ft := f.Type.(type) {
			case *configv1.Filter_Mock:
				e.log.Debug("applying filter", "type", "mock", "index", i)
				ok, err = e.checkMock(context.Background(), req, ft.Mock)
			case *configv1.Filter_Oidc:
				e.log.Debug("applying filter", "type", "oidc", "index", i)
				ok, err = e.checkOidc(context.Background(), req, ft.Oidc)
			case *configv1.Filter_OidcOverride:
				e.log.Debug("applying filter", "type", "oidc_override", "index", i)
				ok, err = e.checkOidc(context.Background(), req, ft.OidcOverride)
			}

			// If there is an error just return it without a verdict, and let the Envoy ext_authz
			// failure policy decide if the request can continue or not.
			if err != nil {
				return nil, err
			}

			log.Debug("filter evaluation", "index", i, "result", ok, "error", err)

			if !ok {
				return deny(codes.PermissionDenied, fmt.Sprintf("%s[%d] filter denied the request", c.Name, i)), nil
			}
		}

		// Return OK if the chain matched and all filters allowed the request
		return allow, nil
	}

	if e.cfg.AllowUnmatchedRequests {
		return allow, nil
	}

	return deny(codes.PermissionDenied, "no chains matched"), nil
}

// checkMock checks the given request against the given mock configuration.
func (e *ExtAuthZFilter) checkMock(_ context.Context, _ *envoy.CheckRequest, mock *mockv1.MockConfig) (bool, error) {
	return mock.Allow, nil
}

// checkOidc checks the given request against the given oidc configuration.
func (e *ExtAuthZFilter) checkOidc(_ context.Context, _ *envoy.CheckRequest, _ *oidcv1.OIDCConfig) (bool, error) {
	// TODO
	return false, nil
}

// matches returns true if the given request matches the given match configuration
func matches(m *configv1.Match, req *envoy.CheckRequest) bool {
	if m == nil {
		return true
	}
	headerValue := req.GetAttributes().GetRequest().GetHttp().GetHeaders()[strings.ToLower(m.Header)]
	if m.GetEquality() != "" {
		return headerValue == m.GetEquality()
	}
	return strings.HasPrefix(headerValue, m.GetPrefix())
}

// mustTriggerCheck returns true if the request must be checked by the authservice filters.
// If any of the TriggerRules match the request path, then the request must be checked.
func mustTriggerCheck(log telemetry.Logger, rules []*configv1.TriggerRule, req *envoy.CheckRequest) bool {
	// If there are no trigger rules, authservice checks should be triggered for all requests.
	// If the request path is empty, (unlikely, but the piece used to match the rules) then trigger the checks.
	if len(rules) == 0 || len(req.GetAttributes().GetRequest().GetHttp().GetPath()) == 0 {
		return true
	}

	for i, rule := range rules {
		l := log.With("rule-index", i)
		if matchTriggerRule(l, rule, req.GetAttributes().GetRequest().GetHttp().GetPath()) {
			return true
		}
	}
	return false
}

func matchTriggerRule(log telemetry.Logger, rule *configv1.TriggerRule, path string) bool {
	if rule == nil {
		return false
	}

	// if any of the excluded paths match, this rule doesn't match
	for i, match := range rule.GetExcludedPaths() {
		l := log.With("excluded-match-index", i)
		if stringMatch(l, match, path) {
			return false
		}
	}

	// if no excluded paths match, and there are no included paths, this rule matches
	if len(rule.GetIncludedPaths()) == 0 {
		return true
	}

	for i, match := range rule.GetIncludedPaths() {
		// if any of the included paths match, this rule matches
		l := log.With("included-match-index", i)
		if stringMatch(l, match, path) {
			return true
		}
	}

	// if none of the included paths match, this rule doesn't match
	return false
}

func stringMatch(log telemetry.Logger, match *configv1.StringMatch, path string) bool {
	switch m := match.GetMatchType().(type) {
	case *configv1.StringMatch_Exact:
		return m.Exact == path
	case *configv1.StringMatch_Prefix:
		return strings.HasPrefix(path, m.Prefix)
	case *configv1.StringMatch_Suffix:
		return strings.HasSuffix(path, m.Suffix)
	case *configv1.StringMatch_Regex:
		b, err := regexp.MatchString(m.Regex, path)
		if err != nil {
			log.Error("error matching regex", err, "regex", m.Regex, "match", false)
		}
		return b
	default:
		return false
	}
}
