package models

type Generator struct {
	GeneratorID    string  `json:"generatorID"`
	GeneratorTopic string  `json:"generatorTopic"`
	Lat            float32 `json:"lat"`
	Lon            float32 `json:"lon"`
	Temperature    Message `json:"temperature"`
	Power          Message `json:"power"`
	Load           Message `json:"load"`
	CurrentFuel    Message `json:"currentFuel"`
	Base_fuel      Message `json:"base_fuel"`
	Fuel_used      Message `json:"fuel_used"`
}
