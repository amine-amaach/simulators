package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/amine-amaach/simulators/ioTSensorsMQTT/utils"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
)

type MQTTService struct{}

var mqttSvc *MQTTService

func NewMQTTService() *MQTTService {
	if mqttSvc == nil {
		return &MQTTService{}
	}
	return mqttSvc
}

func (MQTTService) Connect(ctx context.Context, logger *log.Logger, cfg *utils.Config) *autopaho.ConnectionManager {

	MQTTServerURL, err := url.Parse(cfg.MQTTBroker.ServerURL)

	if err != nil {
		logger.Panicf(utils.Colorize(fmt.Sprintf("Server name not valid ❌ %v", err), utils.Red))
	}

	cliCfg := autopaho.ClientConfig{
		BrokerUrls:        []*url.URL{MQTTServerURL},
		KeepAlive:         cfg.MQTTBroker.KeepAlive,
		ConnectRetryDelay: time.Duration(cfg.MQTTBroker.RetryDelay) * time.Second,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			logger.Println(utils.Colorize("MQTT Connection up ✅", utils.Green))
		},
		OnConnectError: func(err error) {
			logger.Printf(utils.Colorize(fmt.Sprintf("Error whilst attempting connection ❌ %s\n", err), utils.Red))
		},
		ClientConfig: paho.ClientConfig{
			ClientID: cfg.MQTTBroker.ClientID,
			OnClientError: func(err error) {
				logger.Printf(utils.Colorize(fmt.Sprintf("Server requested disconnect ✖️ %s\n", err), utils.Yellow))
			},
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					logger.Printf(utils.Colorize(fmt.Sprintf("Server requested disconnect ✖️ %s\n", d.Properties.ReasonString), utils.Yellow))
				} else {
					logger.Printf(utils.Colorize(fmt.Sprintf("Server requested disconnect ✖️ reason code: %d\n", d.ReasonCode), utils.Yellow))
				}
			},
		},
	}

	// TODO : Configure TLS connections

	cliCfg.SetUsernamePassword(cfg.MQTTBroker.User, []byte(cfg.MQTTBroker.Pwd))

	cm, err := autopaho.NewConnection(ctx, cliCfg)
	if err != nil {
		logger.Println(utils.Colorize(fmt.Sprintf("EdgeConnector failed initial MQTT connection to %s ❌ [%v]", cliCfg.BrokerUrls, err), utils.Red))
	}

	// AwaitConnection will return immediately if connection is up; adding this call stops publication whilst
	// connection is unavailable.
	cm.AwaitConnection(ctx)
	return cm
}

func (MQTTService) Publish(ctx context.Context, cm *autopaho.ConnectionManager, cfg *utils.Config, logger *log.Logger, payload float64, topic string) {
	logger.Print(utils.Colorize(fmt.Sprintf("%s[%s] ⌛\n", "Sending Message Payload for : ", topic), utils.Blue))

	msg, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	pubStruct := &paho.Publish{
		QoS:        cfg.MQTTBroker.Qos,
		Topic:      topic,
		Retain:     cfg.MQTTBroker.Retain,
		Properties: nil,
		Payload:    msg,
	}

	pubResp, publishErr := cm.Publish(ctx, pubStruct)

	if publishErr != nil {
		logger.Println(utils.Colorize(fmt.Sprintf("MQTT publish error ❌ [%s] / [%+v]", publishErr, pubResp), utils.Red))
	} else if pubResp.ReasonCode != 0 && pubResp.ReasonCode != 16 { // 16 = Server received message but there are no subscribers
		logger.Println(utils.Colorize(fmt.Sprintf("Reason code %d received ❌\n", pubResp.ReasonCode), utils.Red))
	} else {
		logger.Println(utils.Colorize(fmt.Sprintf("✅ %s[%s] : %.4f\n", "Message Payload Published to ", topic, payload), utils.Green))
	}
}
