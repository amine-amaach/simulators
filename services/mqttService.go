package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/amine-amaach/simulators/services/models"
	"github.com/amine-amaach/simulators/utils"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"go.uber.org/zap"
)

type mqttService struct{}

func NewMqttService() *mqttService {
	return &mqttService{}
}

//Connect implements the mqttPort interface by creating an MQTT client.
func (svc mqttService) Connect(ctx context.Context, logger *zap.SugaredLogger, cfg utils.Config) (*autopaho.ConnectionManager, context.CancelFunc, error) {

	MQTTServerURL, err := url.Parse(cfg.ServerURL)

	if err != nil {
		logger.Panic("Server name not valid ❌ %v", err)
	}

	cliCfg := autopaho.ClientConfig{
		BrokerUrls:        []*url.URL{MQTTServerURL},
		KeepAlive:         cfg.KeepAlive,
		ConnectRetryDelay: time.Duration(cfg.RetryDelay) * time.Second,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			logger.Info(utils.Colorize("MQTT Connection up ✅", utils.Green))
		},
		OnConnectError: func(err error) {
			logger.Errorf("Error whilst attempting connection ❌ %s\n", err)
		},
		ClientConfig: paho.ClientConfig{
			ClientID:      cfg.ClientID,
			OnClientError: func(err error) { logger.Errorf("Server requested disconnect ✖️ %s\n", err) },
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					logger.Warnf("Server requested disconnect ✖️ %s\n", d.Properties.ReasonString)
				} else {
					logger.Warnf("Server requested disconnect ✖️ reason code: %d\n", d.ReasonCode)
				}
			},
		},
	}

	// TODO : Configure TLS connections

	cliCfg.SetUsernamePassword(cfg.User, []byte(cfg.Pwd))

	ctx, cancel := context.WithCancel(ctx)
	cm, err := autopaho.NewConnection(ctx, cliCfg)
	if err != nil {
		logger.Errorf("EdgeConnector failed initial MQTT connection to %s ❌ [%v]", cliCfg.BrokerUrls, err)
	}
	// AwaitConnection will return immediately if connection is up; adding this call stops publication whilst
	// connection is unavailable.
	err = cm.AwaitConnection(ctx)
	return cm, cancel, err

}

//Close implements the mqttPort interface by closing the MQTT client.
func (svc mqttService) Close(cancel context.CancelFunc, logger *zap.SugaredLogger) {
	logger.Info(utils.Colorize("MQTT Connection Closed ✖️\n", utils.Magenta))
	if cancel != nil {
		cancel()
	}
}

// Publish implements the mqttPort interface by publishing the payload message to the corresponding topic
func (svc mqttService) Publish(ctx context.Context, cm *autopaho.ConnectionManager, logger *zap.SugaredLogger, msgPayloads map[string]json.RawMessage, qos byte, retain bool) {
	for topic, payload := range msgPayloads {
		logger.Infow(utils.Colorize(fmt.Sprintf("%s[%s] ⌛\n", "Sending Message Payload for : ", topic), utils.Yellow))
		pubStruct := &paho.Publish{
			QoS:        qos,
			Topic:      topic,
			Retain:     retain,
			Properties: nil,
			Payload:    payload,
		}
		pubResp, publishErr := cm.Publish(ctx, pubStruct)
		if publishErr != nil {
			logger.Errorf("MQTT publish error ❌ [%s] / [%+v]", publishErr, pubResp)
		} else {
			parse(payload, logger, topic)
		}
	}
}

// parse() decodes(unmarshals) the payload message to log the published message payload.
func parse(payload json.RawMessage, logger *zap.SugaredLogger, topic string) {
	type pgPayload struct {
		Name string
		Lat  float32
		Lon  float32
	}
	// Find the payload type(struct) and log it, else do nothing.
	message := models.Message{}
	err := json.Unmarshal(payload, &message)
	if err == nil && message.ItemId == "" {
		gen := pgPayload{}
		err = json.Unmarshal(payload, &gen)
		if err == nil && gen.Name != "" {
			logger.Infow(utils.Colorize(fmt.Sprintf("%s[%s] ✅\n", "Message Payload Published to : ", topic), utils.Green),
				"Name", gen.Name, "Lat", gen.Lat, "Lon", gen.Lon)
		}
	} else if message.ItemId != "" {
		logger.Infow(utils.Colorize(fmt.Sprintf("%s[%s] ✅\n", "Message Payload Published to : ", topic), utils.Green),
			"ItemName", message.ItemName, "ItemValue", message.ItemValue,
			"ChangedTimestamp", message.ChangedTimestamp, "ItemOldValue", message.ItemOldValue)
	}
}
