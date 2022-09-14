package services

import (
	"context"
	"time"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	"github.com/sirupsen/logrus"
)

var (
	// EoD Node Seq and BdSeq
	Seq   int64 = 0
	BdSeq int64 = 0
)

type EdgeNodeSvc struct {
	Namespace      string
	GroupeId       string
	NodeId         string
	Devices        map[string]*DeviceSvc
	SessionHandler *MqttSessionSvc
}

func NewEdgeNodeInstance(
	ctx context.Context,
	namespace, groupeId, nodeId string,
	bdSeq int64,
	log *logrus.Logger,
	mqttConfigs *component.MQTTConfig,
) (*EdgeNodeSvc, error) {
	log.Debugln("Setting up a new EoN Node instance 🔔")

	mqttSession := &MqttSessionSvc{
		Log:         log,
		MqttConfigs: *mqttConfigs,
	}

	willTopic := namespace + "/" + groupeId + "/NDEATH/" + nodeId

	// Building up the Death Certificate MQTT Payload.
	payload := model.NewSparkplubBPayload(time.Now()).
		AddMetric(*model.NewMetric("bdSeq", 4, bdSeq))
		//  sparkplug.DataType_Int64 == 4

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.Errorln("Error encoding the sparkplug payload ⛔")
		return nil, err
	}

	err = mqttSession.EstablishMqttSession(ctx, willTopic, bytes)

	if err != nil {
		log.Errorln("Error establishing MQTT session ⛔")
		return nil, err
	}

	return &EdgeNodeSvc{
		Namespace:      namespace,
		GroupeId:       groupeId,
		NodeId:         nodeId,
		SessionHandler: mqttSession,
		Devices:        make(map[string]*DeviceSvc),
	}, err
}

func (e *EdgeNodeSvc) AddDevice(device *DeviceSvc, log *logrus.Logger) *EdgeNodeSvc {
	if device != nil {
		if device.DeviceId != "" {
			if _, exists := e.Devices[device.DeviceId]; exists {
				log.WithField("Device Id", device.DeviceId).Warnln("Device exists 🔔")
				return e
			}
			e.Devices[device.DeviceId] = device
			log.WithField("Device Id", device.DeviceId).Infoln("Device added successfully ✅")
			return e
		}
		log.Errorln("Device id not set ⛔")
		return e
	}
	log.Errorln("Device is not configured ⛔")
	return e
}

func (e *EdgeNodeSvc) ShutdownDevice(ctx context.Context, deviceId string, log *logrus.Logger) *EdgeNodeSvc {
	deviceToShutdown, exists := e.Devices[deviceId]
	if !exists {
		log.WithField("Device Id", deviceId).Warnln("Device not found 🔔")
		return e
	}
	delete(e.Devices, deviceId)
	log.WithField("Device Id", deviceId).Debugln("Shuting down all attached sensors.. 🔔")
	for _, sim := range deviceToShutdown.Simulators {
		sim.Shutdown <- true
		*sim.IsAssigned = false
	}
	deviceToShutdown.SessionHandler.Close(ctx, deviceId)
	deviceToShutdown = nil
	log.WithField("Device Id", deviceId).Infoln("Device removed successfully ✅")
	return e
}

// Used to get the sequence number
func GetNextSeqNum(log *logrus.Logger) int64 {
	retSeq := Seq
	if Seq == 256 {
		Seq = 0
	} else {
		Seq++
	}
	log.WithField("Seq", retSeq).Debugf("Next Seq : %d 🔔\n", Seq)
	return retSeq
}

func IncrementBdSeqNum(log *logrus.Logger) {
	if BdSeq == 256 {
		BdSeq = 0
	} else {
		BdSeq++
	}
	log.WithField("Next BdSeq", BdSeq).Debugln("BdSeq incremented 🔔")
}
