package component

type Device struct {
	DeviceId        string      `mapstructure:"device_id"`
	StoreAndForward bool        `mapstructure:"store_and_forward"`
	TTL             uint32      `mapstructure:"time_to_live"`
	Simulators      []IoTSensor `mapstructure:"simulators"`
}
