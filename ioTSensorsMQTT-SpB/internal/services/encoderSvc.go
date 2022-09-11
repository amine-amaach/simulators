package services

import (
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
)

type SparkplugBEncoder struct{}

func (*SparkplugBEncoder) GetBytes(payload model.SparkplugBPayload) *sparkplug.Payload {
	protoMsg := sparkplug.Payload{}

	// Set the timestamp
	if !payload.Timestamp.IsZero() {
		time := uint64(payload.Timestamp.UnixMilli())
		protoMsg.Timestamp = &time
	}

	// Set the sequence number
	protoMsg.Seq = &payload.Seq

	// Set the UUID if defined
	if payload.Uuid != "" {
		protoMsg.Uuid = &payload.Uuid
	}

	// Set the metrics
	for _, metric := range payload.Metrics {
		protoMetric := &sparkplug.Payload_Metric{}
		if err := metric.ConvertMetric(protoMetric); err != nil {
			// Todo Log error
			return nil
		}
		protoMsg.Metrics = append(protoMsg.Metrics, protoMetric)
	}

	// Set Body
	protoMsg.Body = payload.Body

	return &protoMsg
}
