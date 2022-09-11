package model

import sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"

type Parameter struct {
	// The name of the parameter
	Name string `json:"name,omitempty"`

	// The data type of the parameter
	Type sparkplug.DataType `json:"type,omitempty"`

	// The value of the parameter
	Value any `json:"value,omitempty"`
}
