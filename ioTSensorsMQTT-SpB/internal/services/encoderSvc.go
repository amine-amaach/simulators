package services

import (
	"errors"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

var (
	ErrEncodingFailed = errors.New("failed to encode Sparkplug payload")
	ErrEmptyPayload   = errors.New("got empty sparkplug payload")
)

type SparkplugBEncoder struct {
	log *logrus.Logger
}

func NewSparkplugBEncoder(log *logrus.Logger) *SparkplugBEncoder {
	return &SparkplugBEncoder{
		log: log,
	}
}

func (encoder *SparkplugBEncoder) GetBytes(payload *model.SparkplugBPayload) ([]byte, error) {
	if payload == nil {
		encoder.log.Errorln("Empty sparkplug payload ⛔")
		return nil, ErrEmptyPayload
	}

	encoder.log.Debugln("Encoding a new sparkplug B payload.. 🔔")
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
		if err := metric.ConvertMetric(protoMetric, encoder.log); err != nil {
			encoder.log.WithFields(logrus.Fields{
				"Metric name":  metric.Name,
				"Metric alias": metric.Alias,
				"ERROR Msg":    err,
			}).Errorln("Failed to convert Metric to sparkplug B model, skipping.. ⛔")
			continue
		}
		protoMsg.Metrics = append(protoMsg.Metrics, protoMetric)
	}

	// Set Body
	protoMsg.Body = payload.Body

	// Write the new address book back to disk.
	out, err := proto.Marshal(&protoMsg)
	if err != nil {
		encoder.log.WithFields(logrus.Fields{
			"msg": err,
		}).Errorln("Failed to encode Sparkplug B payload ⛔")
		return nil, ErrEncodingFailed
	}
	encoder.log.Debugln("Sparkplug B payload encoding : Successful ✅")
	return out, nil
}
