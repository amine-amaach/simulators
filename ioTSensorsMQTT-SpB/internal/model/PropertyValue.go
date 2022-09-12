package model

import (
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/sirupsen/logrus"
)

type PropertyValue struct {
	Type   sparkplug.DataType `json:"type,omitempty"`
	Value  any                `json:"value,omitempty"`
	IsNull bool               `json:"is_null,omitempty"`
}

func (propertyValue *PropertyValue) convertPropertyValue(log *logrus.Logger) *sparkplug.Payload_PropertyValue {
	protoPropertyValue := &sparkplug.Payload_PropertyValue{}
	if err := propertyValue.getPropertyValue(protoPropertyValue); err != nil {
		log.WithFields(logrus.Fields{
			"msg":         err,
		}).Errorln("Failed to convert PropertyValue to sparkplug B model ⛔")
		return nil
	}
	propertyType := uint32(propertyValue.Type.Number())
	protoPropertyValue.Type = &propertyType
	protoPropertyValue.IsNull = &propertyValue.IsNull
	return protoPropertyValue
}

func (propertyValue *PropertyValue) getPropertyValue(protoMetric *sparkplug.Payload_PropertyValue) error {
	switch propertyValue.Type {
	case sparkplug.DataType_Boolean:
		value, ok := propertyValue.Value.(bool)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_PropertyValue_BooleanValue{BooleanValue: value}
	case sparkplug.DataType_Float:
		value, ok := propertyValue.Value.(float32)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_PropertyValue_FloatValue{FloatValue: value}
	case sparkplug.DataType_Double:
		value, ok := propertyValue.Value.(float64)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_PropertyValue_DoubleValue{DoubleValue: value}
	case sparkplug.DataType_Int32:
		value, ok := propertyValue.Value.(uint32)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_PropertyValue_IntValue{IntValue: value}
	case sparkplug.DataType_Int64:
		value, ok := propertyValue.Value.(uint64)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_PropertyValue_LongValue{LongValue: value}
	case sparkplug.DataType_String:
		value, ok := propertyValue.Value.(string)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_PropertyValue_StringValue{StringValue: value}
	default:
		return ErrUnsupportedDataType
	}
	return nil
}
