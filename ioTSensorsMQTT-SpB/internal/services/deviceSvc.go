package services

import (
	"fmt"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/simulators"
	"github.com/sirupsen/logrus"
)

type DeviceSvc struct {
	Namespace string
	GroupeId  string
	NodeId    string
	DeviceId  string
	// Each device will have each own Seq and BdSeq
	DeviceSeq   int64
	DeviceBdSeq int64
	// Simulated sensors attached to this device
	Simulators     map[string]*simulators.IoTSensorSim
	SessionHandler *MqttSessionSvc
}

func NewDeviceInstance(
	namespace, groupeId, nodeId, deviceId string,
	log *logrus.Logger,
	MqttConfigs *component.MQTTConfig,
) *DeviceSvc {
	log.Debugln("Setting up a new device instance 🔔")
	deviceInstance := DeviceSvc{
		Namespace:   namespace,
		GroupeId:    groupeId,
		NodeId:      nodeId,
		DeviceId:    deviceId,
		DeviceSeq:   0,
		DeviceBdSeq: 0,
		Simulators:  make(map[string]*simulators.IoTSensorSim),
	}
	mqttSession := NewMqttSessionSvc(log, MqttConfigs)
	willTopic := namespace + "/" + groupeId + "/DDEATH/" + nodeId + "/" + deviceId
	err := mqttSession.SetClientOptions(willTopic, deviceInstance.GetNextDeviceSeqNum(log))
	if err != nil {
		log.Errorf("Failed to set the MQTT client options : %v ⛔\n", err)
		return nil
	}

	err = mqttSession.EstablishMqttSession()
	if err != nil {
		log.Errorf("%v ⛔\n", err)
		return nil
	}
	deviceInstance.SessionHandler = mqttSession
	return &deviceInstance
}

func (d *DeviceSvc) AddSimulator(sim *simulators.IoTSensorSim, log *logrus.Logger) {
	if sim == nil {
		log.Errorln("Sensor not defined ⛔")
		return
	}

	if *sim.IsAssigned {
		log.WithFields(logrus.Fields{
			"Sensor Id": sim.SensorId,
			"Device Id": d.DeviceId,
		}).Warnln("Sensor not available 🔔")
		return
	}

	if sim.SensorId != "" {
		log.WithField("Sensor Id", sim.SensorId).Debugln("Adding sensor.. 🔔")
		d.Simulators[sim.SensorId] = sim
		*sim.IsAssigned = true
		log.WithFields(logrus.Fields{
			"Sensor Id": sim.SensorId,
			"Device Id": d.DeviceId,
		}).Infoln("Sensor added successfully ✅")
		return
	} else {
		log.Errorln("Sensor id is empty ⛔")
	}
}

func (d *DeviceSvc) ShutdownSimulator(sensorId string, log *logrus.Logger) {
	sensorToShutdown, exists := d.Simulators[sensorId]
	if !exists {
		log.WithFields(logrus.Fields{
			"Sensor Id": sensorId,
			"Device Id": d.DeviceId,
		}).Warnln("Sensor not found 🔔")
		return
	}

	log.WithFields(logrus.Fields{
		"Sensor Id": sensorId,
		"Device Id": d.DeviceId,
	}).Debugln("Removing sensor.. 🔔")

	// Free the sensor
	*sensorToShutdown.IsAssigned = false
	// Sensor is off but it can't be reused again by another device
	sensorToShutdown.Shutdown <- true
	delete(d.Simulators, sensorId)

	log.WithFields(logrus.Fields{
		"Sensor Id": sensorId,
		"Device Id": d.DeviceId,
	}).Infoln("Sensor removed successfully ✅")
}

func (d *DeviceSvc) RunSimulators(log *logrus.Logger) {
	for _, sim := range d.Simulators {
		sim.Run(log)
	}
}

func (d *DeviceSvc) Publisher(log *logrus.Logger) {
	topic := d.Namespace + "/" + d.GroupeId + "/DDATA/" + d.NodeId + "/" + d.DeviceId
	for _, sim := range d.Simulators {
		go func(s *simulators.IoTSensorSim) {
			for sensorData := range s.SensorData {
				// log.WithField("Sensor Data ", sensorData).Infoln("New data point from ", s.SensorId)
				token := d.SessionHandler.MqttClient.Publish(topic+"/"+s.SensorId, 0, false, fmt.Sprint(sensorData))
				token.Wait()
				if err := token.Error(); err != nil {
					log.WithFields(logrus.Fields{
						"Device Id": d.DeviceId,
						"Sensor Id": s.SensorId,
						"Topic":     topic + "/" + s.SensorId,
						"Err":       err,
					}).Warnln("Couldn't publish DDATA to the broker")
				} else {
					log.WithFields(logrus.Fields{
						"Device Id": d.DeviceId,
						"Sensor Id": s.SensorId,
						"Sensor Data": sensorData,
						"Topic":     topic + "/" + s.SensorId,
					}).Infoln("DDATA Published to the broker ✅")
				}
			}
		}(sim)
	}
}

func (d *DeviceSvc) GetNextDeviceSeqNum(log *logrus.Logger) int64 {
	retSeq := Seq
	if d.DeviceSeq == 256 {
		d.DeviceSeq = 0
	} else {
		d.DeviceSeq++
	}
	log.WithFields(
		logrus.Fields{
			"Device Id":  d.DeviceId,
			"Device Seq": d.DeviceSeq,
		},
	).Debugf("Next Device Seq : %d 🔔\n", Seq)
	return retSeq
}

func (d *DeviceSvc) IncrementDeviceBdSeqNum(log *logrus.Logger) {
	if d.DeviceBdSeq == 256 {
		d.DeviceBdSeq = 0
	} else {
		d.DeviceBdSeq++
	}
	log.WithFields(
		logrus.Fields{
			"Device Id":    d.DeviceId,
			"Device BdSeq": d.DeviceSeq,
		},
	).Debugln("Device BdSeq incremented 🔔")
}
