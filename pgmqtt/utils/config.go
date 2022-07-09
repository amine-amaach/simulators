package utils

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// This Config struct will hold all configuration variables of the application that we read from file
// or environment variables.
type Config struct {
	//Viper uses the mapstructure package under the hood for unmarshaling values.
	ServerURL                  string `mapstructure:"MQTT_SERVER_URL"`
	User                       string `mapstructure:"MQTT_SERVER_USER"`
	Pwd                        string `mapstructure:"MQTT_SERVER_PWD"`
	Retain                     bool   `mapstructure:"MQTT_SERVER_RETAIN"`
	Qos                        byte   `mapstructure:"MQTT_SERVER_QOS"`
	ClientID                   string `mapstructure:"MQTT_CLIENT_ID"`
	KeepAlive                  uint16 `mapstructure:"MQTT_KEEP_ALIVE"`
	RetryDelay                 uint16 `mapstructure:"MQTT_RETRY_DELAY"`
	Area                       string `mapstructure:"AREA"`
	Site                       string `mapstructure:"SITE"`
	RandomDelayBetweenMessages bool   `mapstructure:"RANDOM_DELAY_BETWEEN_MESSAGES"`
	DelayBetweenMessagesMin    uint16 `mapstructure:"DELAY_BETWEEN_MESSAGES_MIN"`
	DelayBetweenMessagesMax    uint16 `mapstructure:"DELAY_BETWEEN_MESSAGES_MAX"`
	GeneratorsNumber           int    `mapstructure:"GENERATORS_NUMBER"`
	GeneratorsLimitNumber      int    `mapstructure:"GENERATORS_NUMBER_LIMIT"`
}

func NewConfig(logger *zap.SugaredLogger) *Config {
	cfg := &Config{}
	cfg.LoadConfig(logger)
	return cfg
}

// LoadConfig reads configuration from file or environment variables.
func (config *Config) LoadConfig(logger *zap.SugaredLogger) {
	viper.AddConfigPath("./configs/")
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	// AutomaticEnv() automatically override values that it has read from config file with the values of
	// the corresponding environment variables if they exist.
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		// Environment variables have the highest priority!
		logger.Warn(Colorize("Config not found ❌ Using default values 🔧\n", Magenta),
			Colorize(err.Error(), Magenta))
		config.setDefaults(logger)
		return
	} else {
		logger.Info(Colorize("Config Found : Loading Config ⌛", Cyan))
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		config.setDefaults(logger)
	}
}

// Set default values : setDefaults only used when no value is provided by the user via config or ENV.
func (config *Config) setDefaults(logger *zap.SugaredLogger) {

	viper.SetDefault("MQTT_SERVER_URL", "mqtt://localhost:1883")
	viper.SetDefault("MQTT_SERVER_USER", "admin")
	viper.SetDefault("MQTT_SERVER_PWD", "eminEMQXe")
	viper.SetDefault("MQTT_SERVER_QOS", 0)
	viper.SetDefault("MQTT_SERVER_RETAIN", false)
	viper.SetDefault("MQTT_CLIENT_ID", "someID")
	viper.SetDefault("MQTT_KEEP_ALIVE", 300)
	viper.SetDefault("MQTT_RETRY_DELAY", 10)
	viper.SetDefault("SITE", "Site")
	viper.SetDefault("AREA", "Area")
	viper.SetDefault("RANDOM_DELAY_BETWEEN_MESSAGES", true)
	viper.SetDefault("DELAY_BETWEEN_MESSAGES_MIN", 5)
	viper.SetDefault("DELAY_BETWEEN_MESSAGES_MAX", 10)
	viper.SetDefault("GENERATORS_NUMBER", 3)
	viper.SetDefault("GENERATORS_LIMIT", 50)

	err := viper.Unmarshal(&config)
	if err != nil {
		// Panics if the tags on the fields of the structure are not properly set
		logger.Panic(Colorize("Failed to marshal Configs ❌", Magenta),
			Colorize(err.Error(), Magenta))
	}

}
