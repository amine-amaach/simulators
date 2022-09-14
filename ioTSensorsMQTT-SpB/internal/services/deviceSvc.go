package services

import (
	"context"
	"sync"
	"time"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/simulators"
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/sirupsen/logrus"
)

type DeviceSvc struct {
	Namespace string
	GroupeId  string
	NodeId    string
	DeviceId  string
	// Each device will have each own Seq and BdSeq
	DeviceSeq   uint64
	DeviceBdSeq uint64
	// Simulated sensors attached to this device
	Simulators     map[string]*simulators.IoTSensorSim
	SessionHandler *MqttSessionSvc
	// Retain device's data in the broker
	retain  bool
	connMut sync.RWMutex
}

func NewDeviceInstance(
	ctx context.Context,
	namespace, groupeId, nodeId, deviceId string,
	log *logrus.Logger,
	mqttConfigs *component.MQTTConfig,
) (*DeviceSvc, error) {
	log.Debugln("Setting up a new device instance 🔔")

	deviceInstance := &DeviceSvc{
		Namespace:   namespace,
		GroupeId:    groupeId,
		NodeId:      nodeId,
		DeviceId:    deviceId,
		DeviceSeq:   0,
		DeviceBdSeq: 0,
		retain:      false,
		Simulators:  make(map[string]*simulators.IoTSensorSim),
	}

	mqttSession := &MqttSessionSvc{
		Log:         log,
		MqttConfigs: *mqttConfigs,
	}

	willTopic := namespace + "/" + groupeId + "/DDEATH/" + nodeId + "/" + deviceId

	// Building up the Death Certificate MQTT Payload.
	payload := model.NewSparkplubBPayload(time.Now(), deviceInstance.GetNextDeviceSeqNum(log)).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, deviceInstance.GetNextDeviceSeqNum(log)))

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.Errorln("Error encoding the sparkplug payload ⛔")
		return nil, err
	}

	err = mqttSession.EstablishMqttSession(ctx, willTopic, bytes,
		func(cm *autopaho.ConnectionManager, c *paho.Connack) {
			log.Infoln("MQTT connection up ✅")
		})

	if err != nil {
		log.Errorln("Error establishing MQTT session ⛔")
		return nil, err
	}

	deviceInstance.SessionHandler = mqttSession
	return deviceInstance, err
}

func (d *DeviceSvc) AddSimulator(sim *simulators.IoTSensorSim, log *logrus.Logger) *DeviceSvc {
	if sim == nil {
		log.Errorln("Sensor not defined ⛔")
		return d
	}

	if *sim.IsAssigned {
		log.WithFields(logrus.Fields{
			"Sensor Id": sim.SensorId,
			"Device Id": d.DeviceId,
		}).Warnln("Sensor not available 🔔")
		return d
	}

	if sim.SensorId != "" {
		log.WithField("Sensor Id", sim.SensorId).Debugln("Adding sensor.. 🔔")
		if _, exists := d.Simulators[sim.SensorId]; exists {
			log.WithField("Sensor Id", sim.SensorId).Infoln("Sensors exists.. 🔔")
			return d
		}
		d.Simulators[sim.SensorId] = sim
		*sim.IsAssigned = true
		log.WithFields(logrus.Fields{
			"Sensor Id": sim.SensorId,
			"Device Id": d.DeviceId,
		}).Infoln("Sensor added successfully ✅")
		return d
	} else {
		log.Errorln("Sensor id not defined ⛔")
	}
	return d
}

func (d *DeviceSvc) ShutdownSimulator(sensorId string, log *logrus.Logger) *DeviceSvc {
	sensorToShutdown, exists := d.Simulators[sensorId]
	if !exists {
		log.WithFields(logrus.Fields{
			"Sensor Id": sensorId,
			"Device Id": d.DeviceId,
		}).Warnln("Sensor not found 🔔")
		return d
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
	return d
}

func (d *DeviceSvc) RunSimulators(log *logrus.Logger) *DeviceSvc {
	for _, sim := range d.Simulators {
		if sim.IsRunning {
			log.WithFields(logrus.Fields{
				"Device Id": d.DeviceId,
				"Sensor Id": sim.SensorId,
			}).Warnln("Sensor is already running 🔔")
			continue
		}
		sim.Run(log)
	}
	return d
}

func (d *DeviceSvc) RunPublisher(ctx context.Context, log *logrus.Logger) *DeviceSvc {
	for _, sim := range d.Simulators {
		go func(d *DeviceSvc, s *simulators.IoTSensorSim) {
			for {
				// AwaitConnection will return immediately if connection is up.
				// Adding this call stops publication whilst connection is unavailable.
				err := d.SessionHandler.MqttClient.AwaitConnection(ctx)
				if err != nil { // Should only happen when context is cancelled
					log.Infof("Publisher done (AwaitConnection: %s), Shutdown sensors..\n", err)
					for _, sim := range d.Simulators {
						sim.Shutdown <- true
					}
					return
				}
				select {
				case data := <-s.SensorData:
					d.publishSensorData(ctx, s.SensorId, data, log)
				case _, open := <-s.Shutdown:
					if open {
						log.WithFields(logrus.Fields{
							"Device Id": d.DeviceId,
							"Sensor Id": s.SensorId,
						}).Warnln("Sensor is turning off ⛔")
						// Release this goroutine when the sensor is turning off
						return
					}
				}
			}
		}(d, sim)
	}
	return d
}

// Only a device instance that is permitted to run a simulator
func (d *DeviceSvc) publishSensorData(ctx context.Context, sensorId string, data float64, log *logrus.Logger) {
	topic := d.Namespace + "/" + d.GroupeId + "/DDATA/" + d.NodeId + "/" + d.DeviceId

	d.connMut.RLock()
	cm := d.SessionHandler.MqttClient
	d.connMut.RUnlock()

	if cm == nil {
		log.WithFields(logrus.Fields{
			"Device Id": d.DeviceId,
		}).Warnln("MQTT connection is down ⛔")

		// TODO :: Store data to be sent later

		return
	}

	// Building up the DDATA Payload.
	payload := model.NewSparkplubBPayload(time.Now(), d.GetNextDeviceSeqNum(log)).
		AddMetric(*model.NewMetric(d.DeviceId+"/"+sensorId, 10, data))
		//  sparkplug.DataType_Double == 10

	// Encoding the Death Certificate MQTT Payload.
	msg, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Device Id": d.DeviceId,
			"Sensor Id": sensorId,
			"Err":       err,
		}).Errorln("Error encoding the sparkplug payload, not publishing.. ⛔")
		return
	}

	// log.WithField("Sensor Data ", sensorData).Infoln("New data point from ", s.SensorId)

	// Publish will block so we run it in a goRoutine
	go func(ctx context.Context, cm *autopaho.ConnectionManager, msg []byte) {
		pr, err := cm.Publish(ctx, &paho.Publish{
			QoS:     d.SessionHandler.MqttConfigs.QoS,
			Topic:   topic + "/" + sensorId,
			Payload: msg,
		})
		if err != nil {
			// store data to be sent later
			log.WithFields(logrus.Fields{
				"Device Id": d.DeviceId,
				"Sensor Id": sensorId,
				"Topic":     topic + "/" + sensorId,
			}).Errorln("Couldn't publish DDATA to the broker, retrying again.. ⛔")
		} else if pr.ReasonCode != 0 && pr.ReasonCode != 16 { // 16 = Server received message but there are no subscribers
			log.WithFields(logrus.Fields{
				"Device Id": d.DeviceId,
				"Sensor Id": sensorId,
				"Topic":     topic + "/" + sensorId,
			}).Errorln("reason code %d received ⛔\n", pr.ReasonCode)
		} else {
			log.WithFields(logrus.Fields{
				"Device Id": d.DeviceId,
				"Sensor Id": sensorId,
				"Topic":     topic + "/" + sensorId,
			}).Infoln("DDATA Published to the broker ✅")
		}
	}(ctx, cm, msg)
}

func (d *DeviceSvc) GetNextDeviceSeqNum(log *logrus.Logger) uint64 {
	retSeq := d.DeviceSeq
	if d.DeviceSeq == 256 {
		d.DeviceSeq = 0
	} else {
		d.DeviceSeq++
	}
	log.WithFields(
		logrus.Fields{
			"Device Id":  d.DeviceId,
			"Device Seq": retSeq,
		},
	).Debugf("Next Device Seq : %d 🔔\n", d.DeviceSeq)
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
