package services

import (
	"errors"
	"time"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	nanoid "github.com/matoous/go-nanoid/v2"
	"github.com/sirupsen/logrus"
)

var ErrEmptyClientOptions = errors.New("got empty MQTT client options")

type MqttSessionSvc struct {
	Log               *logrus.Logger
	MqttConfigs       *component.MQTTConfig
	MqttClientOptions *mqtt.ClientOptions
	MqttClient        mqtt.Client
}

func NewMqttSessionSvc(log *logrus.Logger, MqttConfigs *component.MQTTConfig) *MqttSessionSvc {
	return &MqttSessionSvc{
		MqttConfigs: MqttConfigs,
		Log:         log,
	}
}

func (m *MqttSessionSvc) EstablishMqttSession() error {
	if m.MqttClient != nil {
		m.Log.Warnln("MQTT session already exists 🔔")
		return nil
	}

	if m.MqttClientOptions == nil {
		m.Log.Errorln("Empty MQTT client options ⛔")
		return ErrEmptyClientOptions
	}

	// Create new Mqtt client
	client := mqtt.NewClient(m.MqttClientOptions)

	tok := client.Connect()
	m.Log.Infof("Trying to establish an MQTT Session to %v 🔔\n", m.MqttConfigs.URLs)
	tok.Wait()
	if err := tok.Error(); err != nil {
		m.Log.Errorln("Error Establishing an MQTT Session ⛔")
		return err
	}
	m.Log.Infoln("MQTT Session Established ✅")
	m.MqttClient = client
	return nil
}

func (m *MqttSessionSvc) SetClientOptions(willTopic string, bdSeq int64) error {
	m.Log.Debugln("Setting up an MQTT client options 🔔")
	if m.MqttConfigs == nil {
		m.Log.Errorln("Empty MQTT client options ⛔")
		return ErrEmptyClientOptions
	}

	connectTimeout, err := time.ParseDuration(m.MqttConfigs.ConnectTimeout)
	if err != nil {
		m.Log.Errorf("Unable to parse connect timeout duration string: %w ⛔", err)
		return err
	}

	// Setup the MQTT connection parameters
	config := mqtt.NewClientOptions().
		SetAutoReconnect(true).
		SetCleanSession(m.MqttConfigs.CleanSession).
		SetConnectTimeout(connectTimeout).
		SetKeepAlive(time.Duration(m.MqttConfigs.KeepAlive))

	if m.MqttConfigs.ClientID != "" {
		config.SetClientID(m.MqttConfigs.ClientID)
	} else {
		autoClientId, err := nanoid.New()
		if err != nil {
			m.Log.Errorln("Unable to auto-generate client id ⛔")
			return err
		}
		config.SetClientID(autoClientId)
	}

	// Set MQTT servers urls
	for _, u := range m.MqttConfigs.URLs {
		config = config.AddBroker(u)
	}

	if m.MqttConfigs.User != "" {
		config.SetUsername(m.MqttConfigs.User)
	}

	if m.MqttConfigs.Password != "" {
		config.SetPassword(m.MqttConfigs.Password)
	}

	// TODO: set TLS
	// if m.MqttConfigs.TLS.Enabled {}

	// Building up the Death Certificate MQTT Payload.
	payload := model.NewSparkplubBPayload(time.Now()).
		AddMetric(*model.NewMetric("bdSeq", 4, bdSeq))
		//  sparkplug.DataType_Int64 == 4

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(m.Log).GetBytes(payload)
	if err != nil {
		return err
	}

	// Setup the Death Certificate Topic/Payload into the MQTT session
	config.SetBinaryWill(willTopic, bytes, 0, false)

	m.MqttClientOptions = config
	return nil
}

func (m *MqttSessionSvc) Close()  {
	m.Log.WithField("ClientId", m.MqttConfigs.ClientID).Debugln("Closing MQTT connection.. 🔔")
	if m.MqttClient != nil {
		m.MqttClient.Disconnect(0)
		m.MqttClient = nil
	}
}