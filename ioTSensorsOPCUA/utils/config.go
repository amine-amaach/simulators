package utils

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

type UserIds struct {
	Username string `mapstructure:"Username"`
	Password string `mapstructure:"Password"`
}

type params struct {
	Name              string  `mapstructure:"Name"`
	Mean              float64 `mapstructure:"Mean"`
	StandardDeviation float64 `mapstructure:"StandardDeviation"`
}

type Config struct {
	UserIds                          []UserIds   `mapstructure:"USERIDs"`
	SET_DELAY_BETWEEN_MESSAGES       int         `mapstructure:"SET_DELAY_BETWEEN_MESSAGES"`
	RANDOMIZE_DELAY_BETWEEN_MESSAGES bool        `mapstructure:"RANDOMIZE_DELAY_BETWEEN_MESSAGES"`
	SimulatorsParams                 []params    `mapstructure:"SIMULATORS"`
	Certificate                      Certificate `mapstructure:"CERTIFICATE"`
}
type Certificate struct {
	AdditionalHosts []string `mapstructure:"HOSTS"`
}

func GetConfig() Config {
	v := viper.New()
	var config Config

	v.SetConfigName("config")    // name of config file (without extension)
	v.SetConfigType("json")      // REQUIRED if the config file does not have the extension in the name
	v.AddConfigPath("./configs") // look for config in the working directory

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			log.Println(Colorize("Config file not found! using default configs..", Yellow))
			setDefault(v)
		} else {
			log.Println(Colorize("Config file was found but another error was produced : ", Red))
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
	} else {
		log.Println(Colorize("Config file found and successfully parsed", Green))
	}

	err := v.Unmarshal(&config)
	if err != nil {
		panic(fmt.Errorf("unable to decode into struct %w", err))
	}

	return config
}

func setDefault(v *viper.Viper) {
	v.SetDefault("USERIDs", []UserIds{
		{
			Username: "root",
			Password: "secret",
		},
	})
	v.SetDefault("SET_DELAY_BETWEEN_MESSAGES", 5)
	v.SetDefault("RANDOMIZE_DELAY_BETWEEN_MESSAGES", true)
	v.SetDefault("SIMULATORS", []params{
		{
			Name:              "Temperature",
			Mean:              20.0,
			StandardDeviation: 5.0,
		},
		{
			Name:              "Pressure",
			Mean:              80.0,
			StandardDeviation: 7.0,
		},
		{
			Name:              "Air Quality",
			Mean:              13.0,
			StandardDeviation: 3.0,
		},
	})
	v.SetDefault("CERTIFICATE", Certificate{
		AdditionalHosts: []string{},
	})
}

// Foreground colors.
const (
	Black uint8 = iota + 30
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

// Colorize colorizes a string by a given color.
func Colorize(s string, c uint8) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", c, s)
}
