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

package internal

import (
	"errors"
	"fmt"
	"os"

	"github.com/tetratelabs/run"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/tetrateio/authservice-go/config/gen/go/v1"
	oidcv1 "github.com/tetrateio/authservice-go/config/gen/go/v1/oidc"
)

var (
	_ run.Config = (*LocalConfigFile)(nil)

	// ErrInvalidPath is returned when the configuration file path is invalid.
	ErrInvalidPath = errors.New("invalid path")
	// ErrInvalidOIDCOverride is returned when the OIDC override is invalid.
	ErrInvalidOIDCOverride = errors.New("invalid OIDC override")
	// ErrDuplicateOIDCConfig is returned when the OIDC configuration is duplicated.
	ErrDuplicateOIDCConfig = errors.New("duplicate OIDC configuration")
)

// LocalConfigFile is a run.Config that loads the configuration file.
type LocalConfigFile struct {
	path string
	// Config is the loaded configuration.
	Config configv1.Config
}

// Name returns the name of the unit in the run.Group.
func (l *LocalConfigFile) Name() string { return "Local configuration file" }

// FlagSet returns the flags used to customize the config file location.
func (l *LocalConfigFile) FlagSet() *run.FlagSet {
	flags := run.NewFlagSet("Local Config File flags")
	flags.StringVar(&l.path, "config-path", "/etc/authservice/config.json", "configuration file path")
	return flags
}

// Validate and load the configuration file.
func (l *LocalConfigFile) Validate() error {
	if l.path == "" {
		return ErrInvalidPath
	}

	content, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}

	if err = protojson.Unmarshal(content, &l.Config); err != nil {
		return err
	}

	// Validate OIDC configuration overrides
	for _, fc := range l.Config.Chains {
		for _, f := range fc.Filters {
			if l.Config.DefaultOidcConfig != nil && f.GetOidc() != nil {
				return fmt.Errorf("%w: in chain %q OIDC filter and default OIDC configuration cannot be used together",
					ErrDuplicateOIDCConfig, fc.Name)
			}
			if l.Config.DefaultOidcConfig == nil && f.GetOidcOverride() != nil {
				return fmt.Errorf("%w: in chain %q OIDC override filter requires a default OIDC configuration",
					ErrInvalidOIDCOverride, fc.Name)
			}
		}
	}

	// Overrides for non-supported values
	l.Config.Threads = 1

	// Merge the OIDC overrides with the default OIDC configuration so that
	// we can properly validate the settings and  all filters have only one
	// location where the OIDC configuration is defined.
	mergeOIDCConfigs(&l.Config)

	// Now that all defaults are set and configurations are merged, validate all final settings
	return l.Config.ValidateAll()
}

// mergeOIDCConfigs merges the OIDC overrides with the default OIDC configuration so that
// all filters have only one location where the OIDC configuration is defined.
func mergeOIDCConfigs(cfg *configv1.Config) {
	for _, fc := range cfg.Chains {
		for _, f := range fc.Filters {
			// Merge the OIDC overrides and populate the normal OIDC field instead so that
			// consumers of the config always have an up-to-date object
			if f.GetOidcOverride() != nil {
				oidc := proto.Clone(cfg.DefaultOidcConfig).(*oidcv1.OIDCConfig)
				proto.Merge(oidc, f.GetOidcOverride())
				f.Type = &configv1.Filter_Oidc{Oidc: oidc}
			}
		}
	}
	// Clear the default config as it has already been merged. This way there is only one
	// location for the OIDC settings.
	cfg.DefaultOidcConfig = nil
}

func ConfigToJSONString(c *configv1.Config) string {
	b, _ := protojson.Marshal(c)
	return string(b)
}
