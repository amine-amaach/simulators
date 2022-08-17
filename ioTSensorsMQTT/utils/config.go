package utils

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	MQTTBroker mqttBroker  `mapstructure:"MQTT_BROKER"`
	SimParams  []SimParams `mapstructure:"SIMULATORS"`
}

type mqttBroker struct {
	ServerURL            string `mapstructure:"SERVER_URL"`
	User                 string `mapstructure:"SERVER_USER"`
	Pwd                  string `mapstructure:"SERVER_PWD"`
	Retain               bool   `mapstructure:"SERVER_RETAIN"`
	Qos                  byte   `mapstructure:"SERVER_QOS"`
	ClientID             string `mapstructure:"CLIENT_ID"`
	KeepAlive            uint16 `mapstructure:"KEEP_ALIVE"`
	RetryDelay           uint16 `mapstructure:"RETRY_DELAY"`
	RootTopic            string `mapstructure:"ROOT_TOPIC"`
	DelayBetweenMessages int `mapstructure:"SET_DELAY_BETWEEN_MESSAGES"`
	RandomizeDelay       bool   `mapstructure:"RANDOMIZE_DELAY_BETWEEN_MESSAGES"`
}

type SimParams struct {
	Name              string  `mapstructure:"Name"`
	Mean              float64 `mapstructure:"Mean"`
	StandardDeviation float64 `mapstructure:"StandardDeviation"`
}

var cfg *Config

func GetConfig() *Config {

	if cfg == nil {
		v := viper.New()

		v.SetConfigName("config")    // name of config file (without extension)
		v.SetConfigType("json")      // REQUIRED if the config file does not have the extension in the name
		v.AddConfigPath("./configs") // look for config in the working directory

		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				// config file not found; ignore error if desired
				log.Println(Colorize("config file not found! using default configs..", Yellow))
				setDefault(v)
			} else {
				log.Println(Colorize("config file was found but another error was produced : ", Red))
				panic(fmt.Errorf("fatal error config file: %w", err))
			}
		} else {
			log.Println(Colorize("config file found and successfully parsed", Green))
		}

		err := v.Unmarshal(&cfg)
		if err != nil {
			panic(fmt.Errorf("unable to decode into struct %w", err))
		}

		return cfg
	}
	return cfg
}

func setDefault(v *viper.Viper) {
	viper.SetDefault("SERVER_URL", "mqtt://broker.hivemq.com:1883")
	viper.SetDefault("SERVER_USER", "")
	viper.SetDefault("SERVER_PWD", "")
	viper.SetDefault("SERVER_QOS", 2)
	viper.SetDefault("SERVER_RETAIN", "true")
	viper.SetDefault("CLIENT_ID", "IoTSensorsMQTT-Simulator")
	viper.SetDefault("KEEP_ALIVE", 300)
	viper.SetDefault("RETRY_DELAY", 10)
	viper.SetDefault("ROOT_TOPIC", "IoTSensorsMQTT")
	viper.SetDefault("SET_DELAY_BETWEEN_MESSAGES", 5)
	viper.SetDefault("RANDOMIZE_DELAY_BETWEEN_MESSAGES", "true")

	v.SetDefault("SIMULATORS", []SimParams{
		{
			Name:              "Temperature",
			Mean:              20.5,
			StandardDeviation: 5.1,
		},
		{
			Name:              "Pressure",
			Mean:              80.9,
			StandardDeviation: 7.3,
		},
		{
			Name:              "Air Quality",
			Mean:              13.8,
			StandardDeviation: 3.2,
		},
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
