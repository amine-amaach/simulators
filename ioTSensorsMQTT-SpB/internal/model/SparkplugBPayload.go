package model

import (
	"time"
)

type SparkplugBPayload struct {
	Timestamp time.Time `json:"timestamp,omitempty"`
	Metrics   []*Metric `json:"metrics,omitempty"`
	Seq       uint64    `json:"seq,omitempty"`
	Uuid      string    `json:"uuid,omitempty"`
	Body      []byte    `json:"body,omitempty"`
}

func NewSparkplubBPayload(
	timestamp time.Time,
	seq uint64,
) *SparkplugBPayload {
	return &SparkplugBPayload{
		Timestamp: timestamp,
		Seq: seq,
	}
}

func (payload *SparkplugBPayload) AddMetric(metric Metric) *SparkplugBPayload {
	payload.Metrics = append(payload.Metrics, &metric)
	return payload
}

func (payload *SparkplugBPayload) AddMetrics(metrics []Metric) *SparkplugBPayload {
	for _, metric := range metrics {
		payload.AddMetric(metric)
	}
	return payload
}
