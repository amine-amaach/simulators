package component

type MQTTConfig struct {
	URL                   string `mapstructure:"url"`
	QoS                   uint8  `mapstructure:"qos"`
	ClientID              string `mapstructure:"client_id"`
	User                  string `mapstructure:"user"`
	Password              string `mapstructure:"password"`
	KeepAlive             uint16 `mapstructure:"keep_alive"`
	ConnectTimeout        string `mapstructure:"connect_timeout"`
	ConnectRetry          int64  `mapstructure:"connect_retry"`
	CleanStart            bool   `mapstructure:"clean_start"`
	SessionExpiryInterval uint32 `mapstructure:"session_expiry_interval"`
	// TODO : TLS
}
