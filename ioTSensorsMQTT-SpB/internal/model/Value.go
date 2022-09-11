package model

import sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"

type Value struct {
	Type  sparkplug.DataType `json:"type,omitempty"`
	Value any                `json:"value,omitempty"`
}
