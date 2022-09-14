package services

import (
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	// "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	mqtt "github.com/eclipse/paho.golang/paho"
)

type Publisher struct {
	Topic           string
	OutboundPayload model.SparkplugBPayload
	MqttClient      mqtt.Client
}

func NewPublisher(topic string, outboundPayload model.SparkplugBPayload, mqttClient mqtt.Client) *Publisher {
	return &Publisher{
		Topic:           topic,
		OutboundPayload: outboundPayload,
		MqttClient:      mqttClient,
	}
}

// func (publisher *Publisher) publish() {
// 	outboundPayload  := &model.SparkplugBPayload{}
// }
