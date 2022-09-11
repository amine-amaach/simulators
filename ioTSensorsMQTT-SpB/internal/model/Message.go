package model

type Message struct {
	Topic string
	Payload SparkplugBPayload
}

func NewMessage(
	topic string,
	payload SparkplugBPayload,
)  *Message {
	return &Message{
		Topic: topic,
		Payload: payload,
	}
}