package services

import (
	"context"
	"math/rand"
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
	retain bool

	// Sensor Alias, to be used in DDATA, instead of name
	Alias uint64

	StartTime time.Time
	connMut   sync.RWMutex
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
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, 0, deviceInstance.GetNextDeviceSeqNum(log)))

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.Errorln("Error encoding the sparkplug payload ⛔")
		return nil, err
	}

	err = mqttSession.EstablishMqttSession(ctx, willTopic, bytes,
		func(cm *autopaho.ConnectionManager, c *paho.Connack) {
			log.WithFields(logrus.Fields{
				"Groupe Id": deviceInstance.GroupeId,
				"Node Id":   deviceInstance.NodeId,
				"Device Id": deviceInstance.DeviceId,
			}).Infoln("MQTT connection up ✅")
			deviceInstance.PublishBirth(ctx, log)
			log.WithFields(logrus.Fields{
				"Groupe Id": deviceInstance.GroupeId,
				"Node Id":   deviceInstance.NodeId,
				"Device Id": deviceInstance.DeviceId,
			}).Infoln("DBIRTH certificate published successfully ✅")
		})

	if err != nil {
		log.Errorln("Error establishing MQTT session ⛔")
		return nil, err
	}

	deviceInstance.StartTime = time.Now()
	deviceInstance.Alias = uint64(100 + rand.Int63n(10000))
	deviceInstance.SessionHandler = mqttSession
	return deviceInstance, err
}

func (d *DeviceSvc) AddSimulator(ctx context.Context, sim *simulators.IoTSensorSim, log *logrus.Logger) *DeviceSvc {
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

		// Republish DBIRTH certificate including the new sensor
		d.PublishBirth(ctx, log)

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

func (d *DeviceSvc) ShutdownSimulator(ctx context.Context, sensorId string, log *logrus.Logger) *DeviceSvc {
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

	// Republish DBIRTH certificate including the new sensor
	d.PublishBirth(ctx, log)

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

// PublishBirth used to publish the device DBIRTH certificate to the broker.
func (d *DeviceSvc) PublishBirth(ctx context.Context, log *logrus.Logger) *DeviceSvc {
	upTime := int64(time.Since(d.StartTime) / 1e+6)

	// Create the DBIRTH certificate payload

	// The DBIRTH must include a seq number in the payload and it must have a value
	// of one greater than the previous MQTT message from the EoN node. (spB specs)

	// For this simulation, we'll change things up a bit and decouple the MQTT
	// connections for each device (as with the primary application in the specs).
	payload := model.NewSparkplubBPayload(time.Now(), d.GetNextDeviceSeqNum(log)).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, 1, 0)).
		// Add control commands to control the devices in runtime.
		AddMetric(*model.NewMetric("Device Control/Rebirth", sparkplug.DataType_Boolean, 2, false)).
		AddMetric(*model.NewMetric("Device Control/Shutdown", sparkplug.DataType_Boolean, 3, false)).
		// TODO :: Add metadata with new params
		AddMetric(*model.NewMetric("Device Control/AddSimulator", sparkplug.DataType_Boolean, 4, false)).
		AddMetric(*model.NewMetric("Device Control/RemoveSimulator", sparkplug.DataType_Boolean, 5, false)).
		AddMetric(*model.NewMetric("Device Control/UpdateSimulator", sparkplug.DataType_Boolean, 6, false)).
		// Add some properties
		AddMetric(*model.NewMetric("Properties/Parent EoN Node", sparkplug.DataType_String, 7, d.NodeId)).
		AddMetric(*model.NewMetric("Properties/Number of simulators", sparkplug.DataType_Int64, 8, int64(len(d.Simulators)))).
		AddMetric(*model.NewMetric("Properties/Up time ms", sparkplug.DataType_Int64, 9, upTime))

	for _, sim := range d.Simulators {
		var i uint64 = 1
		if sim != nil {
			payload.AddMetric(*model.NewMetric(d.DeviceId+"Sensors/"+sim.SensorId, sparkplug.DataType_Double, sim.Alias, 0.0)).
				AddMetric(*model.NewMetric(d.DeviceId+"Sensors/"+sim.SensorId+"/Minimum delay", sparkplug.DataType_UInt32, sim.Alias+i, sim.DelayMin)).
				AddMetric(*model.NewMetric(d.DeviceId+"Sensors/"+sim.SensorId+"/Maximum delay", sparkplug.DataType_UInt32, sim.Alias+i, sim.DelayMax)).
				AddMetric(*model.NewMetric(d.DeviceId+"Sensors/"+sim.SensorId+"/Randomized", sparkplug.DataType_Boolean, sim.Alias+i, sim.Randomize))
			i++
		}
	}

	// Encoding the BIRTH Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Groupe ID": d.GroupeId,
			"Node ID":   d.NodeId,
			"Device ID": d.DeviceId,
		}).Errorln("Error encoding DBIRTH certificate ⛔")
		// TODO :: retry until published or cancel after timeout // panic for now
		// panic(err)
	}

	_, err = d.SessionHandler.MqttClient.Publish(ctx, &paho.Publish{
		Topic:   d.Namespace + "/" + d.GroupeId + "/DBIRTH/" + d.NodeId,
		QoS:     1,
		Payload: bytes,
	})

	if err != nil {
		log.WithFields(logrus.Fields{
			"Groupe ID": d.GroupeId,
			"Node ID":   d.NodeId,
			"Device ID": d.DeviceId,
			"Err":       err,
		}).Errorln("Error publishing DBIRTH certificate, retrying.. ⛔")
		// TODO :: retry until published or cancel after timeout // panic for now
		// panic(err)
	}

	// Increment the bdSeq number for the next use
	IncrementBdSeqNum(log)

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
	alias := d.Simulators[sensorId].Alias
	payload := model.NewSparkplubBPayload(time.Now(), d.GetNextDeviceSeqNum(log)).
		// Metric name - should only be included on birth
		AddMetric(*model.NewMetric("", 10, alias, data))
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
			Topic:   topic,
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
