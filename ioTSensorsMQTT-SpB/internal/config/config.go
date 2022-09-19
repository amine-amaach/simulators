package config

import (
	"bytes"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Cfg struct {
	MQTTConfig       component.MQTTConfig `mapstructure:"mqtt_config"`
	EoNNodeConfig    component.EdgeNode   `mapstructure:"eon_node"`
	LoggerConfig     component.Logger     `mapstructure:"logger"`
	EnablePrometheus bool                 `mapstructure:"enable_prometheus"`
}

func GetConfigs() Cfg {
	var configs Cfg
	logger := logrus.New()
	v := viper.New()

	v.SetConfigName("config")             // name of config file (without extension)
	v.SetConfigType("json")               // REQUIRED if the config file does not have the extension in the name
	v.AddConfigPath("./internal/config/") // look for config in the working directory
	v.AddConfigPath("./configs/")         // look for config in the working directory
	v.AddConfigPath("/configs/")          // look for config in the working directory

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found
			logger.Errorln("⛔ Config file not found! using default configs ⛔")
			return setDefault(v, logger)
		} else {
			logger.Errorln("Config file was found but another error was produced ⛔")
			panic(err)
		}
	} else {
		logger.Infoln("Config file found")
	}

	err := v.Unmarshal(&configs)
	if err != nil {
		logger.Errorln("Unable to unmarshal configs ⛔")
		panic(err)
	}
	logger.Infoln("Config file parsed successfully ✅")
	return configs
}

func setDefault(v *viper.Viper, log *logrus.Logger) Cfg {
	var configs Cfg

	defaultConfig := []byte(`
	{
		"mqtt_config": {
			"url": "tcp://broker.emqx.io:1883",
			"qos": 1,
			"client_id": "",
			"user": "",
			"password": "",
			"keep_alive": 5,
			"connect_timeout": "30s",
			"connect_retry": 3,
			"clean_start": false,
			"session_expiry_interval" : 60 
		},
	
		"eon_node": {
			"namespace": "spBv1.0",
			"group_id": "IoTSensors",
			"node_id": "SparkplugB",
			"devices": [
				{
					"device_id": "emulatedDevice",
					"store_and_forward": true,
					"time_to_live": 10,
					"simulators": [
						{
							"sensor_id": "Temperature",
							"mean": 30.6,
							"standard_deviation": 3.1,
							"delay_min": 3,
							"delay_max": 6,
							"randomize": true
						}
					]
				},
				{
					"device_id": "anotherEmulatedDevice",
					"store_and_forward": true,
					"time_to_live": 15,
					"simulators": [
						{
							"sensor_id": "Humidity",
							"mean": 40.7,
							"standard_deviation": 2.3,
							"delay_min": 4,
							"delay_max": 10,
							"randomize": false
						}
					]
				}
			]
		},
	
		"logger": {
			"level": "INFO",
			"format": "TEXT",
			"disable_timestamp": false
		},

		"enable_prometheus": true
	}
	`)

	err := v.MergeConfig(bytes.NewReader(defaultConfig))
	if err != nil {
		log.Errorln("Error using default configs, exiting ⛔")
		panic(err)
	}

	err = v.Unmarshal(&configs)
	if err != nil {
		log.Errorln("Unable to unmarshal default configs ⛔")
		panic(err)
	}
	log.Infoln("Default configs parsed successfully ✅")
	return configs
}
