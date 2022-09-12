package services

import (
	"errors"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

var ErrEncodingFailed = errors.New("failed to encode Sparkplug payload")

type SparkplugBEncoder struct{}

func (encoder *SparkplugBEncoder) GetBytes(payload model.SparkplugBPayload, log *logrus.Logger) ([]byte, error) {
	log.Debugln("Encoding a new sparkplug B payload..")
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
		if err := metric.ConvertMetric(protoMetric, log); err != nil {
			log.WithFields(logrus.Fields{
				"Metric Name": metric.Name,
				"msg": err,
			}).Errorln("Failed to convert Metric to sparkplug B model ⛔")
			continue
		}
		protoMsg.Metrics = append(protoMsg.Metrics, protoMetric)
	}

	// Set Body
	protoMsg.Body = payload.Body

	// Write the new address book back to disk.
	out, err := proto.Marshal(&protoMsg)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Seq": payload.Seq,
			"msg": err,
		}).Errorln("Failed to encode Sparkplug B payload ⛔")
		return nil, ErrEncodingFailed
	}
	log.WithFields(logrus.Fields{
		"Seq": payload.Seq,
	}).Infoln("Encoding Sparkplug B payload : Successful ✅")
	return out, nil
}
