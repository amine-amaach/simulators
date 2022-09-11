package model

import (
	"time"
)

type SparkplugBPayload struct {
	Timestamp time.Time          `json:"timestamp,omitempty"`
	Metrics   []*Metric `json:"metrics,omitempty"`
	Seq       uint64             `json:"seq,omitempty"`
	Uuid      string             `json:"uuid,omitempty"`
	Body      []byte             `json:"body,omitempty"`
}

func NewSparkplubBPayload(
	timestamp time.Time, 
	metrics []*Metric,
	seq uint64, uuid string, 
	body []byte,
	) *SparkplugBPayload {
	return &SparkplugBPayload{
		Timestamp: timestamp,
		Metrics: metrics,
		Seq: seq,
		Uuid: uuid,
		Body: body,
	}
}

// func (payload *SparkplugBPayload) addMetric(metric Metric) {
// 	payload.Metrics[metric.Alias] = &metric
// }

// func (payload *SparkplugBPayload) addMetrics(metrics []Metric) {
// 	for _, metric := range metrics {
// 		payload.addMetric(metric)
// 	}

// }
