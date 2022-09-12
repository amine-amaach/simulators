package model

import (
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/sirupsen/logrus"
)

type PropertySet struct {
	Map map[string]*PropertyValue `json:"map,omitempty"`
}

func (propertySet *PropertySet) GetValues(protoPropertySet *sparkplug.Payload_PropertySet) {

}

func (propertySet *PropertySet) GetProperties(log *logrus.Logger) *sparkplug.Payload_PropertySet {
	keys := make([]string, 0, len(propertySet.Map))
	propertyValues := make([]*sparkplug.Payload_PropertyValue, 0, len(propertySet.Map))

	for k, propertyValue := range propertySet.Map {
		if propertyValue == nil || propertyValue.Value == nil || propertyValue.IsNull {
			log.Warnln("Empty property value, 🔔 skipped..")
			continue
		}
		protoPropertyValue := propertyValue.convertPropertyValue(log)
		if protoPropertyValue != nil {
			propertyValues = append(propertyValues, protoPropertyValue)
			keys = append(keys, k)
		} else {
			log.Warnln("Empty property value, 🔔 skipped..")
		}
	}

	return &sparkplug.Payload_PropertySet{
		Keys:   keys,
		Values: propertyValues,
	}
}
