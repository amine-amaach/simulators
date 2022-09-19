package component

type IoTSensor struct {
	SensorId  string  `mapstructure:"sensor_id"`
	Mean      float64 `mapstructure:"mean"`
	Std       float64 `mapstructure:"standard_deviation"`
	DelayMin  uint32  `mapstructure:"delay_min"`
	DelayMax  uint32  `mapstructure:"delay_max"`
	Randomize bool    `mapstructure:"randomize"`
}
