package services

import (
	"context"
	"time"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/matishsiao/goInfo"
	"github.com/sirupsen/logrus"
)

var (
	// EoD Node Seq and BdSeq
	Seq       uint64 = 0
	BdSeq     uint64 = 0
	StartTime time.Time
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
	bdSeq uint64,
	log *logrus.Logger,
	mqttConfigs *component.MQTTConfig,
) (*EdgeNodeSvc, error) {
	log.Debugln("Setting up a new EoN Node instance 🔔")

	mqttSession := &MqttSessionSvc{
		Log:         log,
		MqttConfigs: *mqttConfigs,
	}

	eonNode := &EdgeNodeSvc{
		Namespace:      namespace,
		GroupeId:       groupeId,
		NodeId:         nodeId,
		SessionHandler: mqttSession,
		Devices:        make(map[string]*DeviceSvc),
	}

	willTopic := namespace + "/" + groupeId + "/NDEATH/" + nodeId

	// Building up the Death Certificate MQTT Payload.
	payload := model.NewSparkplubBPayload(time.Now(), GetNextSeqNum(log)).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, bdSeq))

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.Errorln("Error encoding the sparkplug payload ⛔")
		return nil, err
	}

	err = mqttSession.EstablishMqttSession(ctx, willTopic, bytes,
		func(cm *autopaho.ConnectionManager, c *paho.Connack) {
			log.Infoln("MQTT connection up ✅")
			eonNode.PublishBirth(ctx, log)
			log.WithFields(logrus.Fields{
				"Groupe Id": eonNode.GroupeId,
				"Node Id":   eonNode.NodeId,
			}).Infoln("NBIRTH certificate published successfully ✅")
		})

	if err != nil {
		log.Errorln("Error establishing MQTT session ⛔")
		return nil, err
	}

	StartTime = time.Now()
	return eonNode, err
}

// PublishBirth used to publish the EoN node NBIRTH certificate to the broker.
func (e *EdgeNodeSvc) PublishBirth(ctx context.Context, log *logrus.Logger) *EdgeNodeSvc {
	props, _ := goInfo.GetInfo()
	upTime := int64(time.Since(StartTime) / 1e+6)
	// Create the EoN Node BIRTH payload
	payload := model.NewSparkplubBPayload(time.Now(), GetNextSeqNum(log)).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, BdSeq)).
		AddMetric(*model.NewMetric("Up Time ms", sparkplug.DataType_Int64, upTime).SetAlias(2)).
		AddMetric(*model.NewMetric("Node Control/Rebirth", sparkplug.DataType_Boolean, false).SetAlias(3)).
		AddMetric(*model.NewMetric("Node Control/Reboot", sparkplug.DataType_Boolean, false).SetAlias(4)).
		AddMetric(*model.NewMetric("Node Control/Shutdown", sparkplug.DataType_Boolean, false).SetAlias(5)).
		AddMetric(*model.NewMetric("Properties/OS", sparkplug.DataType_String, props.OS).SetAlias(6)).
		AddMetric(*model.NewMetric("Properties/Kernel", sparkplug.DataType_String, props.Kernel).SetAlias(7)).
		AddMetric(*model.NewMetric("Properties/Core", sparkplug.DataType_String, props.Core).SetAlias(8)).
		AddMetric(*model.NewMetric("Properties/CPUs", sparkplug.DataType_Int32, int32(props.CPUs)).SetAlias(9)).
		AddMetric(*model.NewMetric("Properties/Platform", sparkplug.DataType_String, props.Platform).SetAlias(10)).
		AddMetric(*model.NewMetric("Properties/Hostname", sparkplug.DataType_String, props.Hostname).SetAlias(11))

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.Errorln("Error encoding the EoN Node BIRTH certificate, exiting.. ⛔")
		// TODO :: retry until published or cancel after timeout // panic for now
		panic(err)
	}

	_, err = e.SessionHandler.MqttClient.Publish(ctx, &paho.Publish{
		Topic:   e.Namespace + "/" + e.GroupeId + "/NBIRTH/" + e.NodeId,
		QoS:     1,
		Payload: bytes,
	})

	if err != nil {
		log.WithField("Err", err).Errorln("Error publishing the EoN Node BIRTH certificate, retrying.. ⛔")
		// TODO :: retry until published or cancel after timeout // panic for now
		panic(err)
	}

	return e
}

// AddDevice used to add/attach a given device to the EoN Node
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

// ShutdownDevice used to shutdown a given device, publish its DDEATH and detached it from the EoN Node.
func (e *EdgeNodeSvc) ShutdownDevice(ctx context.Context, deviceId string, log *logrus.Logger) *EdgeNodeSvc {
	deviceToShutdown, exists := e.Devices[deviceId]
	if !exists {
		log.WithField("Device Id", deviceId).Warnln("Device not found 🔔")
		return e
	}
	delete(e.Devices, deviceId)
	log.WithField("Device Id", deviceId).Debugln("Shutdown all attached sensors.. 🔔")
	for _, sim := range deviceToShutdown.Simulators {
		sim.Shutdown <- true
		*sim.IsAssigned = false
	}

	// Building up the Death Certificate MQTT Payload.
	payload := model.NewSparkplubBPayload(time.Now(), GetNextSeqNum(log)).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, deviceToShutdown.GetNextDeviceSeqNum(log)))

	// The Edge of Network (EoN) Node is responsible for publishing DDEATH of its devices.
	// When the EoN Node shuts down unexpectedly, the broker will send its NDEATH as well as
	// all of its attached devices. (Each device sends its DDEATH when initializing connection)

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Device ID": deviceId,
			"Err":       err,
			"Info":      "Couldn't create DDEATH certificate",
		}).Errorln("Error encoding the sparkplug payload ⛔")
		return e
	}

	_, err = e.SessionHandler.MqttClient.Publish(ctx, &paho.Publish{
		Topic:   e.Namespace + "/" + e.GroupeId + "/DDEATH/" + e.NodeId + "/" + deviceId,
		QoS:     1,
		Payload: bytes,
	})

	if err != nil {
		log.WithFields(logrus.Fields{
			"Device ID": deviceId,
			"Err":       err,
			"Info":      "Device is turned off but couldn't publish DDEATH certificate",
		}).Errorln("Error publishing DDEATH certificate ⛔")
		return e
	}

	deviceToShutdown.SessionHandler.Close(ctx, deviceId)
	deviceToShutdown = nil
	log.WithField("Device Id", deviceId).Infoln("Device removed successfully ✅")
	return e
}

// GetNextSeqNum used to get the sequence number
func GetNextSeqNum(log *logrus.Logger) uint64 {
	retSeq := Seq
	if Seq == 256 {
		Seq = 0
	} else {
		Seq++
	}
	log.WithField("Seq", retSeq).Debugf("Next Seq : %d 🔔\n", Seq)
	return retSeq
}

// IncrementBdSeqNum used to increment the Bd sequence number
func IncrementBdSeqNum(log *logrus.Logger) {
	if BdSeq == 256 {
		BdSeq = 0
	} else {
		BdSeq++
	}
	log.WithField("Next BdSeq", BdSeq).Debugln("BdSeq incremented 🔔")
}
