package component

type MQTTConfig struct {
	URL                   string `json:"url,omitempty"`
	QoS                   uint8  `json:"qo_s,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	CleanStart            bool   `json:"clean_start,omitempty"`
	SessionExpiryInterval uint32 `json:"session_expiry_interval,omitempty"`
	User                  string `json:"user,omitempty"`
	Password              string `json:"password,omitempty"`
	ConnectTimeout        string `json:"connect_timeout,omitempty"`
	KeepAlive             uint16 `json:"keep_alive,omitempty"`
	// How long to wait between connection attempts (defaults to 10s)
	ConnectRetry int64 `json:"connect_retry,omitempty"`
	// TODO : TLS
}

// Returns default configs
func NewMQTTConfig() *MQTTConfig {
	return &MQTTConfig{
		URL:                   "",
		QoS:                   1,
		ClientID:              "",
		CleanStart:            true,
		SessionExpiryInterval: 60,
		User:                  "",
		Password:              "",
		ConnectTimeout:        "10s",
		KeepAlive:             10,
		ConnectRetry:          5,
	}
}
