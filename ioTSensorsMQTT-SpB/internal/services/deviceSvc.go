package services

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/model"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/simulators"
	sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"
	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

// DeviceSvc struct describes the properties of a device
type DeviceSvc struct {
	Namespace string
	GroupId   string
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

	// Store and forward in-memory store
	Enabled bool

	// Period to keep data in the store before deleting it.
	TTL uint32 // Default 10 minutes

	// Simulated sensors data type == float64
	CacheStore *ttlcache.Cache[string, float64]
}

// NewDeviceInstance used to instantiate a new instance of a device.
func NewDeviceInstance(
	ctx context.Context,
	namespace, groupId, nodeId, deviceId string,
	log *logrus.Logger,
	mqttConfigs *component.MQTTConfig,
	ttl uint32,
	enabled bool,
) (*DeviceSvc, error) {
	log.Debugln("Setting up a new device instance 🔔")

	d := &DeviceSvc{
		Namespace:   namespace,
		GroupId:     groupId,
		NodeId:      nodeId,
		DeviceId:    deviceId,
		DeviceSeq:   0,
		DeviceBdSeq: 0,
		retain:      false,
		Simulators:  make(map[string]*simulators.IoTSensorSim),
		TTL:         ttl,
		Enabled:     enabled,
	}

	// If store and forward enabled
	if d.Enabled {
		d.CacheStore = ttlcache.New(
			ttlcache.WithTTL[string, float64](time.Duration(d.TTL) * time.Minute),
		)
	}

	mqttSession := &MqttSessionSvc{
		Log:         log,
		MqttConfigs: *mqttConfigs,
	}

	willTopic := d.Namespace + "/" + d.GroupId + "/DDEATH/" + d.NodeId + "/" + d.DeviceId

	// Building up the Death Certificate MQTT Payload.
	payload := model.NewSparkplubBPayload(time.Now(), d.GetNextDeviceSeqNum(log)).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, 0, d.GetNextDeviceSeqNum(log)))

	// Encoding the Death Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.Errorln("Error encoding the sparkplug payload ⛔")
		return nil, err
	}

	err = mqttSession.EstablishMqttSession(ctx, willTopic, bytes,
		func(cm *autopaho.ConnectionManager, c *paho.Connack) {
			// On connection up
			log.WithFields(logrus.Fields{
				"Groupe Id": d.GroupId,
				"Node Id":   d.NodeId,
				"Device Id": d.DeviceId,
			}).Infoln("MQTT connection up ✅")

			if d.Enabled && d.CacheStore.Len() > 0 {
				CachedMsgs.Set(float64(d.CacheStore.Len()))
				for key, value := range d.CacheStore.Items() {
					sensorId := strings.Split(key, ":")[0]
					log.WithFields(logrus.Fields{
						"Groupe Id": d.GroupId,
						"Node Id":   d.NodeId,
						"Device Id": d.DeviceId,
						"Key":       key,
					}).Infoln("Republishing unacknowledged messages.. 🔔")
					// Keep retrying publishing the data to the broker until we get
					// PUBACK or the TTL expires.
					go d.publishSensorData(ctx, sensorId, value.Value(), log)
				}
				// Clear the in-memory store
				d.CacheStore.DeleteAll()
			}

			// Subscribe to device control commands
			topic := d.Namespace + "/" + d.GroupId + "/DCMD/" + d.NodeId + "/" + d.DeviceId
			if _, err := cm.Subscribe(ctx, &paho.Subscribe{
				Subscriptions: map[string]paho.SubscribeOptions{
					topic: {QoS: mqttConfigs.QoS},
				},
			}); err != nil {
				log.Infof("Failed to subscribe (%s). This is likely to mean no messages will be received. ⛔\n", err)
				return
			}
			log.WithField("Topic", topic).Infoln("MQTT subscription made ✅")

		}, paho.NewSingleHandlerRouter(func(p *paho.Publish) {
			d.OnMessageArrived(ctx, p, log)
		}),
	)

	if err != nil {
		log.Errorln("Error establishing MQTT session ⛔")
		return nil, err
	}

	d.StartTime = time.Now()
	d.Alias = uint64(100 + rand.Int63n(10000))
	d.SessionHandler = mqttSession
	return d, err
}

// PublishBirth used to publish the device DBIRTH certificate to the broker.
func (d *DeviceSvc) PublishBirth(ctx context.Context, log *logrus.Logger) {
	upTime := int64(time.Since(d.StartTime) / 1e+6)

	// Prevent race condition on the seq number when building/publishing
	d.connMut.RLock()
	seq := d.GetNextDeviceSeqNum(log)
	d.connMut.RUnlock()

	// Create the DBIRTH certificate payload

	// The DBIRTH must include a seq number in the payload and it must have a value
	// of one greater than the previous MQTT message from the EoN node. (spB specs)

	// For this simulation, we'll change things up a bit and decouple the MQTT
	// connections for each device (as with the primary application in the specs).
	payload := model.NewSparkplubBPayload(time.Now(), seq).
		AddMetric(*model.NewMetric("bdSeq", sparkplug.DataType_UInt64, 1, d.DeviceBdSeq)).
		AddMetric(*model.NewMetric("Device Id", sparkplug.DataType_String, 10, d.DeviceId)).
		AddMetric(*model.NewMetric("Node Id", sparkplug.DataType_String, 11, d.NodeId)).
		AddMetric(*model.NewMetric("Group Id", sparkplug.DataType_String, 11, d.GroupId)).
		// Add control commands to control the devices in runtime.
		AddMetric(*model.NewMetric("Device Control/Rebirth", sparkplug.DataType_Boolean, 2, false)).
		AddMetric(*model.NewMetric("Device Control/OFF", sparkplug.DataType_Boolean, 3, false)).
		AddMetric(*model.NewMetric("Device Control/AddSimulator", sparkplug.DataType_Boolean, 4, false)).
		AddMetric(*model.NewMetric("Device Control/RemoveSimulator", sparkplug.DataType_Boolean, 5, false)).
		AddMetric(*model.NewMetric("Device Control/UpdateSimulator", sparkplug.DataType_Boolean, 6, false)).
		// Add some properties
		AddMetric(*model.NewMetric("Properties/Number of simulators", sparkplug.DataType_Int64, 8, int64(len(d.Simulators)))).
		AddMetric(*model.NewMetric("Properties/Up time ms", sparkplug.DataType_Int64, 9, upTime))

	for _, sim := range d.Simulators {
		var i uint64 = 1
		if sim != nil {
			payload.AddMetric(*model.NewMetric(d.DeviceId+"/Sensors/"+sim.SensorId, sparkplug.DataType_Double, sim.Alias, 0.0)).
				AddMetric(*model.NewMetric(d.DeviceId+"/Sensors/"+sim.SensorId+"/Minimum delay", sparkplug.DataType_UInt32, sim.Alias+i+1, sim.DelayMin)).
				AddMetric(*model.NewMetric(d.DeviceId+"/Sensors/"+sim.SensorId+"/Maximum delay", sparkplug.DataType_UInt32, sim.Alias+i+2, sim.DelayMax)).
				AddMetric(*model.NewMetric(d.DeviceId+"/Sensors/"+sim.SensorId+"/Randomized", sparkplug.DataType_Boolean, sim.Alias+i+3, sim.Randomize))
			i++
		}
	}

	// Encoding the BIRTH Certificate MQTT Payload.
	bytes, err := NewSparkplugBEncoder(log).GetBytes(payload)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Groupe ID": d.GroupId,
			"Node ID":   d.NodeId,
			"Device ID": d.DeviceId,
		}).Errorln("Error encoding DBIRTH certificate ⛔")
		return
	}

	_, err = d.SessionHandler.MqttClient.Publish(ctx, &paho.Publish{
		Topic:   d.Namespace + "/" + d.GroupId + "/DBIRTH/" + d.NodeId + "/" + d.DeviceId,
		QoS:     1,
		Payload: bytes,
	})

	if err != nil {
		d.connMut.RLock()
		if d.DeviceSeq == 0 {
			d.DeviceSeq = 256
		} else {
			d.DeviceSeq--
		}
		d.connMut.RUnlock()
		log.WithFields(logrus.Fields{
			"Groupe ID": d.GroupId,
			"Node ID":   d.NodeId,
			"Device ID": d.DeviceId,
			"Err":       err,
		}).Errorln("Error publishing DBIRTH certificate, retrying.. ⛔")
		return
	} else {
		log.WithFields(logrus.Fields{
			"Groupe Id": d.GroupId,
			"Node Id":   d.NodeId,
			"Device Id": d.DeviceId,
		}).Infoln("DBIRTH certificate published successfully ✅")

		// Increment the bdSeq number for the next use
		IncrementBdSeqNum(log)
	}

}

// OnMessageArrived used to handle the device incoming control commands
func (d *DeviceSvc) OnMessageArrived(ctx context.Context, msg *paho.Publish, log *logrus.Logger) {
	log.WithField("Topic", msg.Topic).Infoln("New DCMD arrived 🔔")

	var payloadTemplate sparkplug.Payload_Template
	err := proto.Unmarshal(msg.Payload, &payloadTemplate)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Topic": msg.Topic,
			"Err":   err,
		}).Errorln("Failed to unmarshal DCMD payload ⛔")
		return
	}

	for _, metric := range payloadTemplate.Metrics {
		switch *metric.Name {
		case "Device Control/Rebirth":
			if value, ok := metric.GetValue().(*sparkplug.Payload_Metric_BooleanValue); !ok {
				log.WithFields(logrus.Fields{
					"Topic": msg.Topic,
					"Value": value,
				}).Errorln("Wrong data type received for this DCMD ⛔")
			} else if value.BooleanValue {
				d.PublishBirth(ctx, log)
			}

		case "Device Control/OFF":
			if value, ok := metric.GetValue().(*sparkplug.Payload_Metric_BooleanValue); !ok {
				log.WithFields(logrus.Fields{
					"Topic": msg.Topic,
					"Value": value,
				}).Errorln("Wrong data type received for this DCMD ⛔")
			} else if value.BooleanValue {
				for _, sim := range d.Simulators {
					d.ShutdownSimulator(ctx, sim.SensorId, log)
				}
				log.WithField("Device Id", d.DeviceId).Infoln("Device turned off successfully ✅")
			}

		case "Device Control/AddSimulator":
			if value, ok := metric.GetValue().(*sparkplug.Payload_Metric_BooleanValue); !ok {
				log.WithFields(logrus.Fields{
					"Topic": msg.Topic,
					"Value": value,
				}).Errorln("Wrong data type received for this DCMD ⛔")
			} else if value.BooleanValue {
				type sensorParams struct {
					name      string
					mean      float64
					std       float64
					delayMin  uint32
					delayMax  uint32
					randomize bool
				}
				newSensor := sensorParams{}
				for _, param := range payloadTemplate.Parameters {
					if *param.Name == "SensorId" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_StringValue); ok {
							newSensor.name = name.StringValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor id ⛔")
							return
						}
					}

					if *param.Name == "Mean" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_DoubleValue); ok {
							newSensor.mean = name.DoubleValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor mean value ⛔")
							return
						}
					}

					if *param.Name == "Std" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_DoubleValue); ok {
							newSensor.std = name.DoubleValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor Std value ⛔")
							return
						}
					}

					if *param.Name == "DelayMin" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_IntValue); ok {
							newSensor.delayMin = name.IntValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor min delay value ⛔")
							return
						}
					}

					if *param.Name == "DelayMax" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_IntValue); ok {
							newSensor.delayMax = name.IntValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor max delay value ⛔")
							return
						}
					}

					if *param.Name == "Randomize" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_BooleanValue); ok {
							newSensor.randomize = name.BooleanValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor randomize value ⛔")
							return
						}
					}
				}

				d.AddSimulator(ctx,
					simulators.NewIoTSensorSim(
						newSensor.name,
						newSensor.mean,
						newSensor.std,
						newSensor.delayMin,
						newSensor.delayMax,
						newSensor.randomize,
					), log,
				).RunSimulators(log).RunPublisher(ctx, log)

			}

		case "Device Control/UpdateSimulator":
			if value, ok := metric.GetValue().(*sparkplug.Payload_Metric_BooleanValue); !ok {
				log.WithFields(logrus.Fields{
					"Topic": msg.Topic,
					"Value": value,
				}).Errorln("Wrong data type received for this DCMD ⛔")
			} else if value.BooleanValue {

				newParams := simulators.UpdateSensorParams{}

				for _, param := range payloadTemplate.Parameters {
					if *param.Name == "SensorId" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_StringValue); ok {
							if _, exists := d.Simulators[name.StringValue]; !exists {
								log.WithFields(logrus.Fields{
									"Topic":     msg.Topic,
									"Name":      *param.Name,
									"Sensor Id": name.StringValue,
								}).Errorln("Sensor doesn't exist ⛔")
								return
							}
							newParams.SensorId = name.StringValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor id ⛔")
							return
						}
					}

					if *param.Name == "Mean" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_DoubleValue); ok {
							newParams.Mean = name.DoubleValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor mean value ⛔")
							return
						}
					}

					if *param.Name == "Std" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_DoubleValue); ok {
							newParams.Std = name.DoubleValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor Std value ⛔")
							return
						}
					}

					if *param.Name == "DelayMin" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_IntValue); ok {
							newParams.DelayMin = name.IntValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor min delay value ⛔")
							return
						}
					}

					if *param.Name == "DelayMax" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_IntValue); ok {
							newParams.DelayMax = name.IntValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor max delay value ⛔")
							return
						}
					}

					if *param.Name == "Randomize" {
						if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_BooleanValue); ok {
							newParams.Randomize = name.BooleanValue
						} else {
							log.WithFields(logrus.Fields{
								"Topic": msg.Topic,
								"Name":  *param.Name,
							}).Errorln("Failed to parse sensor randomize value ⛔")
							return
						}
					}
				}
				// Now we can update the sensor parameters
				d.Simulators[newParams.SensorId].Update <- newParams
			}

		case "Device Control/RemoveSimulator":
			for _, param := range payloadTemplate.Parameters {
				if *param.Name == "SensorId" {
					if name, ok := param.Value.(*sparkplug.Payload_Template_Parameter_StringValue); ok {
						d.ShutdownSimulator(ctx, name.StringValue, log)
						return
					} else {
						log.WithFields(logrus.Fields{
							"Topic": msg.Topic,
							"Name":  *param.Name,
						}).Errorln("Failed to parse sensor id ⛔")
						return
					}
				}
			}
			log.WithFields(logrus.Fields{
				"Topic": msg.Topic,
				"Name":  *metric.Name,
			}).Warnln("Sensor id was not found ⛔")

		default:
			log.Errorln("DCMD not defined ⛔")
		}
	}
}

// AddSimulator used to attach a simulated sensor to the device
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
			log.WithField("Sensor Id", sim.SensorId).Warnln("Sensors exists.. 🔔")
			return d
		}

		d.Simulators[sim.SensorId] = sim
		*sim.IsAssigned = true
		sim.IsRunning = false

		log.WithFields(logrus.Fields{
			"Sensor Id": sim.SensorId,
			"Device Id": d.DeviceId,
		}).Infoln("Sensor added successfully ✅")
		d.PublishBirth(ctx, log)
		return d
	} else {
		log.Errorln("Sensor id not defined ⛔")
	}
	return d
}

// ShutdownSimulator used to turn off a device and detach it for the device
func (d *DeviceSvc) ShutdownSimulator(ctx context.Context, sensorId string, log *logrus.Logger) *DeviceSvc {
	d.connMut.RLock()
	defer d.connMut.RUnlock()
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
	d.PublishBirth(ctx, log)
	return d
}

// RunSimulators used to run all the simulated sensors attached to the device
func (d *DeviceSvc) RunSimulators(log *logrus.Logger) *DeviceSvc {
	for _, sim := range d.Simulators {
		if sim.IsRunning {
			continue
		}
		sim.Run(log)
	}
	return d
}

// RunPublisher used to publish all the DDATA to the broker
func (d *DeviceSvc) RunPublisher(ctx context.Context, log *logrus.Logger) *DeviceSvc {
	for _, sim := range d.Simulators {
		go func(d *DeviceSvc, s *simulators.IoTSensorSim) {
			for {
				select {
				case <-d.SessionHandler.MqttClient.Done():
					log.Infoln("MQTT session terminated, cleaning up.. 🔔")
					for _, sim := range d.Simulators {
						d.ShutdownSimulator(ctx, sim.SensorId, log)
					}
					return
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

// publishSensorData used by RunPublisher to prepare the payload of a sensor and publishes it to the broker.
func (d *DeviceSvc) publishSensorData(ctx context.Context, sensorId string, data float64, log *logrus.Logger) {
	// Preventing race condition between goroutines when building/publishing payloads.
	d.connMut.RLock()
	defer d.connMut.RUnlock()

	if d.Simulators[sensorId] == nil {
		return
	}

	// Only a device instance that is permitted to run a simulator attached to it.
	topic := d.Namespace + "/" + d.GroupId + "/DDATA/" + d.NodeId + "/" + d.DeviceId

	cm := d.SessionHandler.MqttClient
	seq := d.GetNextDeviceSeqNum(log)

	if cm == nil {
		log.WithFields(logrus.Fields{
			"Device Id": d.DeviceId,
		}).Warnln("MQTT connection is closed 🔔")
		return
	}

	// Publish will block so we run it in a goRoutine
	go func(ctx context.Context, cm *autopaho.ConnectionManager) {
		// Building up the DDATA Payload.
		alias := d.Simulators[sensorId].Alias
		payload := model.NewSparkplubBPayload(time.Now(), seq).
			// Metric name - should only be included on birth
			AddMetric(*model.NewMetric("", 10, alias, data))
			//  sparkplug.DataType_Double == 10

		// Encoding the sparkplug Payload.
		msg, err := NewSparkplugBEncoder(log).GetBytes(payload)

		if err != nil {
			log.WithFields(logrus.Fields{
				"Groupe Id": d.GroupId,
				"Node Id":   d.NodeId,
				"Device Id": d.DeviceId,
				"Sensor Id": sensorId,
				"Err":       err,
			}).Errorln("Error encoding the sparkplug payload, not publishing.. ⛔")
			return
		}

		_, err = cm.Publish(ctx, &paho.Publish{
			QoS:     d.SessionHandler.MqttConfigs.QoS,
			Topic:   topic,
			Payload: msg,
		})

		if err != nil {
			if d.Enabled {
				log.Infoln("New data point stored, expires at ",
					d.CacheStore.Set(sensorId+":"+fmt.Sprintf("%d", time.Now().UnixMilli()),
						data,
						ttlcache.DefaultTTL).ExpiresAt().Local().String(), " 🔔",
				)
				CachedMsgs.Inc()

				log.WithFields(logrus.Fields{
					"Groupe Id":       d.GroupId,
					"Node Id":         d.NodeId,
					"Device Id":       d.DeviceId,
					"Sensor Id":       sensorId,
					"Store & Forward": "Enabled",
					"Err":             err,
				}).Errorln("Connection with the MQTT broker is currently down, retrying when connection is up.. ⛔")
				// Don't increment the seq number in failure attempt
				if d.DeviceSeq == 0 {
					d.DeviceSeq = 256
				} else {
					d.DeviceSeq--
				}
			} else {
				log.WithFields(logrus.Fields{
					"Groupe Id":       d.GroupId,
					"Node Id":         d.NodeId,
					"Device Id":       d.DeviceId,
					"Sensor Id":       sensorId,
					"Store & Forward": "Disabled",
					"Err":             err,
					"Device Seq":      seq,
				}).Errorln("Connection with the MQTT broker is currently down, dropping data.. ⛔")
				UnAckMsgs.Inc()
			}

		} else {
			AckMsgs.Inc()
			log.WithFields(logrus.Fields{
				"Groupe Id":  d.GroupId,
				"Node Id":    d.NodeId,
				"Device Id":  d.DeviceId,
				"Sensor Id":  sensorId,
				"Device Seq": seq,
			}).Infoln("✅ DDATA Published to the broker ✅")
		}
	}(ctx, cm)
}

// GetNextDeviceSeqNum used to return and increment the EoN Node sequence number
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

// IncrementDeviceBdSeqNum used to increment the EoN Node Bd sequence number
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
