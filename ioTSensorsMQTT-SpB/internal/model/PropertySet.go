package model

import (
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
)

type PropertySet struct {
	Map map[string]*PropertyValue `json:"map,omitempty"`
}

func (propertySet *PropertySet) GetValues(protoPropertySet *sparkplug.Payload_PropertySet) {

}

func (propertySet *PropertySet) GetProperties() *sparkplug.Payload_PropertySet {
	keys := make([]string, 0, len(propertySet.Map))
	propertyValues := make([]*sparkplug.Payload_PropertyValue, 0, len(propertySet.Map))

	for k, propertyValue := range propertySet.Map {
		if propertyValue == nil || propertyValue.Value == nil || propertyValue.IsNull {
			//TODO log
			continue
		}
		protoPropertyValue := propertyValue.convertPropertyValue()
		if protoPropertyValue != nil {
			//TODO log
			propertyValues = append(propertyValues, protoPropertyValue)
			keys = append(keys, k)
		}
	}

	return &sparkplug.Payload_PropertySet{
		Keys:   keys,
		Values: propertyValues,
	}
}
