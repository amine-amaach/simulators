package component

type MQTTConfig struct {
	URL            string `json:"url,omitempty" yaml:"urls"`
	QoS            uint8  `json:"qos,omitempty" yaml:"qos"`
	ClientID       string `json:"client_id,omitempty" yaml:"client_id"`
	CleanSession   bool   `json:"clean_session,omitempty" yaml:"clean_session"`
	User           string `json:"user,omitempty" yaml:"user"`
	Password       string `json:"password,omitempty" yaml:"password"`
	ConnectTimeout string `json:"connect_timeout,omitempty" yaml:"connect_timeout"`
	KeepAlive      int64  `json:"keepalive,omitempty" yaml:"keepalive"`
	// How long to wait between connection attempts (defaults to 10s)
	ConnectRetry int64 `json:"connect_retry,omitempty" yaml:"connect_retry"`
	// TODO : TLS
}

// Returns default configs
func NewMQTTConfig() *MQTTConfig {
	return &MQTTConfig{
		URL:            "",
		QoS:            1,
		ClientID:       "",
		CleanSession:   true,
		User:           "",
		Password:       "",
		ConnectTimeout: "30s",
		KeepAlive:      30,
		ConnectRetry:   10,
	}
}
