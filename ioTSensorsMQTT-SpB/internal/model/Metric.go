package model

import (
	"errors"
	"time"

	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/sirupsen/logrus"
)

var (
	ErrMetricIsNull        = errors.New("metric is Null")
	ErrMetricValueIsNull   = errors.New("metric value is Null")
	ErrUnsupportedDataType = errors.New("unsupported data type")
	ErrDataTypeConflict    = errors.New("data type conflict")
)

type Metric struct {
	Name         string             `json:"name,omitempty"`
	Alias        uint64             `json:"alias,omitempty"`
	TimeStamp    time.Time          `json:"time_stamp,omitempty"`
	DataType     sparkplug.DataType `json:"data_type,omitempty"`
	IsHistorical bool               `json:"is_historical,omitempty"`
	IsTransient  bool               `json:"is_transient,omitempty"`
	Metadata     *MetaData          `json:"metadata,omitempty"`
	Properties   *PropertySet       `json:"properties,omitempty"`
	IsNull       bool               `json:"is_null,omitempty"`
	Value        any                `json:"value,omitempty"`
}

func NewMetric(
	name string,
	dataType sparkplug.DataType,
	value any,
) *Metric {
	return &Metric{
		Name:     name,
		DataType: dataType,
		Value:    value,
	}
}

func (m *Metric) ConvertMetric(protoMetric *sparkplug.Payload_Metric, log *logrus.Logger) error {
	// Return error if metric is null or value is null
	if m.IsNull || m == nil {
		return ErrMetricIsNull
	}

	if m.Value == nil {
		return ErrMetricValueIsNull
	}

	// Set Value
	if err := m.GetValue(protoMetric, log); err != nil {
		return err
	}

	log.WithFields(logrus.Fields{
		"Metric_name": m.Name,
	}).Debugln("Converting a new sparkplug metric .. 🔔")

	// Set data type
	dataType := uint32(m.DataType.Number())
	protoMetric.Datatype = &dataType

	// Set Name
	if m.Name != "" {
		protoMetric.Name = &m.Name
	}

	// Set Alias
	if m.Alias != 0 {
		protoMetric.Alias = &m.Alias
	}

	// Set Timestamp
	if !m.TimeStamp.IsZero() {
		time := uint64(m.TimeStamp.UnixMilli())
		protoMetric.Timestamp = &time
	}

	// Set IsHistorical
	protoMetric.IsHistorical = &m.IsHistorical

	// Set IsTransient
	protoMetric.IsTransient = &m.IsTransient

	// Set isNull
	protoMetric.IsNull = &m.IsNull

	// Set Metadata
	if m.Metadata != nil {
		m.Metadata.ConvertMetaData(protoMetric)
	}

	// Set Properties
	if m.Properties != nil {
		protoMetric.Properties = m.Properties.GetProperties(log)
	}

	return nil
}

func (m *Metric) GetValue(protoMetric *sparkplug.Payload_Metric, log *logrus.Logger) error {
	log.WithFields(logrus.Fields{
		"Metric_name":     m.Name,
		"Metric_dataType": m.DataType,
	}).Debugln("Parsing metric data type .. 🔔")
	switch m.DataType {
	case sparkplug.DataType_Boolean:
		value, ok := m.Value.(bool)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_BooleanValue{BooleanValue: value}
	case sparkplug.DataType_Float:
		value, ok := m.Value.(float32)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_FloatValue{FloatValue: value}
	case sparkplug.DataType_Double:
		value, ok := m.Value.(float64)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_DoubleValue{DoubleValue: value}
	case sparkplug.DataType_Int32:
		value, ok := m.Value.(int32)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_IntValue{IntValue: uint32(value)}
	case sparkplug.DataType_Int64:
		value, ok := m.Value.(int64)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_LongValue{LongValue: uint64(value)}
	case sparkplug.DataType_UInt32:
		value, ok := m.Value.(uint32)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_IntValue{IntValue: value}
	case sparkplug.DataType_UInt64:
		value, ok := m.Value.(uint64)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_LongValue{LongValue: value}
	case sparkplug.DataType_String:
		value, ok := m.Value.(string)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_StringValue{StringValue: value}
	case sparkplug.DataType_Bytes:
		value, ok := m.Value.([]byte)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_BytesValue{BytesValue: value}
	case sparkplug.DataType_DataSet:
		value, ok := m.Value.(*sparkplug.Payload_DataSet)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_DatasetValue{DatasetValue: value}
	case sparkplug.DataType_Template:
		value, ok := m.Value.(*sparkplug.Payload_Template)
		if !ok {
			return ErrDataTypeConflict
		}
		protoMetric.Value = &sparkplug.Payload_Metric_TemplateValue{TemplateValue: value}
	default:
		return ErrUnsupportedDataType
	}
	return nil
}

func (m *Metric) SetAlias(alias uint64) *Metric {
	m.Alias = alias
	return m
}
