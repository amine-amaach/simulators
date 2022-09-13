package services

import (
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
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
	namespace, groupeId, nodeId string,
	bdSeq int64,
	log *logrus.Logger,
	MqttConfigs *component.MQTTConfig,
) *EdgeNodeSvc {
	mqttSession := NewMqttSessionSvc(log, MqttConfigs)
	willTopic := namespace + "/" + groupeId + "/NDEATH/" + nodeId
	err := mqttSession.SetClientOptions(willTopic, bdSeq)
	if err != nil {
		log.Errorf("Failed to set the MQTT client options : %v ⛔\n", err)
		return nil
	}

	err = mqttSession.EstablishMqttSession()
	if err != nil {
		log.Errorf("%v ⛔\n", err)
		return nil
	}

	return &EdgeNodeSvc{
		Namespace:      namespace,
		GroupeId:       groupeId,
		NodeId:         nodeId,
		SessionHandler: mqttSession,
		Devices:        make(map[string]*DeviceSvc),
	}
}

func (e *EdgeNodeSvc) AddDevice(device *DeviceSvc, log *logrus.Logger) {
	if device != nil {
		if device.DeviceId != "" {
			if _, exists := e.Devices[device.DeviceId]; exists {
				log.WithField("Device Id", device.DeviceId).Warnln("Device exists 🔔")
				return
			}
			e.Devices[device.DeviceId] = device
			log.WithField("Device Id", device.DeviceId).Infoln("Device added successfully ✅")
			return
		}
		log.Errorln("Device id not set ⛔")
		return
	}
	log.Errorln("Device is empty ⛔")

}

func (e *EdgeNodeSvc) ShutdownDevice(deviceId string, log *logrus.Logger) {
	deviceToShutdown, exists := e.Devices[deviceId]
	if !exists {
		log.WithField("Device Id", deviceId).Warnln("Device not found 🔔")
		return
	}
	delete(e.Devices, deviceId)
	deviceToShutdown.SessionHandler.Close()
	// TODO : stop all future goroutines
	deviceToShutdown = nil
	log.WithField("Device Id", deviceId).Infoln("Device removed successfully ✅")
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
