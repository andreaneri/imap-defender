package main

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// AccountPolicyConfig configures Defender shadow diagnostics only.
// It does not enable response pacing or account-specific blocking.
type AccountPolicyConfig struct {
	SoftFailures         int64         `yaml:"soft_failures"`
	HardFailures         int64         `yaml:"hard_failures"`
	BlockGlobalFailures  int64         `yaml:"block_global_failures"`
	BlockCountryFailures int64         `yaml:"block_country_failures"`
	SoftDelay            time.Duration `yaml:"soft_delay"`
	HardDelay            time.Duration `yaml:"hard_delay"`
}

// UnmarshalYAML preserves defaults for omitted fields, including partial maps.
// Explicit zero values remain zero and are rejected by validation.
func (p *AccountPolicyConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("security.account_policy must be a mapping")
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		for value.Kind == yaml.AliasNode {
			value = value.Alias
		}
		switch key.Value {
		case "soft_failures", "hard_failures", "block_global_failures", "block_country_failures":
			if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!int" {
				return fmt.Errorf("security.account_policy.%s must be an integer", key.Value)
			}
		case "soft_delay", "hard_delay":
			if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
				return fmt.Errorf("security.account_policy.%s must be a duration string", key.Value)
			}
		default:
			return fmt.Errorf("unknown security.account_policy field %q", key.Value)
		}
	}
	type plain AccountPolicyConfig
	value := plain(defaultAccountPolicy())
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("security.account_policy: %w", err)
	}
	*p = AccountPolicyConfig(value)
	return nil
}

func (p AccountPolicyConfig) validate() error {
	if p.SoftFailures <= 0 || p.SoftFailures >= p.HardFailures ||
		p.HardFailures >= p.BlockGlobalFailures || p.BlockGlobalFailures > 1_000_000 {
		return fmt.Errorf("security.account_policy requires 0 < soft_failures < hard_failures < block_global_failures <= 1000000")
	}
	if p.BlockCountryFailures <= 0 || p.BlockCountryFailures > p.BlockGlobalFailures {
		return fmt.Errorf("security.account_policy requires 0 < block_country_failures <= block_global_failures")
	}
	if p.SoftDelay <= 0 || p.SoftDelay > p.HardDelay || p.HardDelay > 30*time.Second {
		return fmt.Errorf("security.account_policy requires 0 < soft_delay <= hard_delay <= 30s")
	}
	return nil
}
