package main

import (
	"fmt"
	toml "github.com/pelletier/go-toml"
	"os"
)

// config file structure
type ConfigRepo struct {
	Url   string `toml:"url"`
	User  string `toml:"user"`
	Token string `toml:"token"`
}

type ConfigLocal struct {
	Directory string `toml:"directory"`
}

type ConfigProxy struct {
	Url string `toml:"url"`
}

type ConfigLdap struct {
	Server           string `toml:"url"`
	Dn               string `toml:"dn"`
	Password         string `toml:"password"`
	SearchBaseDn     string `toml:"searchdn"`
	SearchBaseFilter string `toml:"filter"`
}

type Settings struct {
	Engine  ConfigRepo  `toml:"engine"`
	Objects ConfigRepo  `toml:"objects"`
	Local   ConfigLocal `toml:"local"`
	Proxy   ConfigProxy `toml:"proxy"`
	Ldap    ConfigLdap  `toml:"ldap"`
}

type Config struct {
	Settings Settings `toml:"settings"`
}

// gets parameters from a synapse builder config.toml file
func readBuilderConfigFile(path string) (*Config, error) {
	var config_file []byte
	var config *Config
	var err error

	config_file, err = os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Could not read the config file: %s", err)
	}

	err = toml.Unmarshal(config_file, config)
	if err != nil {
		return nil, fmt.Errorf("Could not parse the config file: %s", err)
	}

	return config, nil
}
