package component

type MQTTConfig struct {
	URLs           []string `json:"urls,omitempty" yaml:"urls"`
	QoS            uint8    `json:"qos,omitempty" yaml:"qos"`
	ClientID       string   `json:"client_id,omitempty" yaml:"client_id"`
	CleanSession   bool     `json:"clean_session,omitempty" yaml:"clean_session"`
	User           string   `json:"user,omitempty" yaml:"user"`
	Password       string   `json:"password,omitempty" yaml:"password"`
	ConnectTimeout string   `json:"connect_timeout,omitempty" yaml:"connect_timeout"`
	KeepAlive      int64    `json:"keepalive,omitempty" yaml:"keepalive"`
	// TODO : TLS
}

// Returns default configs
func NewMQTTConfig() *MQTTConfig {
	return &MQTTConfig{
		URLs:           []string{},
		QoS:            1,
		ClientID:       "",
		CleanSession:   true,
		User:           "",
		Password:       "",
		ConnectTimeout: "30s",
		KeepAlive:      30,
	}
}
