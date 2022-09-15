package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/services"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/simulators"
	"github.com/sirupsen/logrus"
)

func main() {

	// TODO ::
	// Each device with a unique context/ same for node
	//

	fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	mqttConfig := component.NewMQTTConfig()
	mqttConfig.ConnectTimeout = "5s"
	mqttConfig.KeepAlive = 10
	mqttConfig.QoS = 1
	mqttConfig.ConnectRetry = 3
	mqttConfig.URL = "tcp://broker.hivemq.com:1883"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node1, err := services.NewEdgeNodeInstance(
		ctx,
		"spBv1.0",
		"groupeId",
		"node01",
		services.BdSeq,
		logger,
		mqttConfig,
	)

	if err != nil {
		panic(err)
	}

	device1, err := services.NewDeviceInstance(
		ctx,
		"spBv1.0",
		"groupeId",
		"node01",
		"device01",
		logger,
		mqttConfig,
		10,
		true,
	)

	if err != nil {
		logger.Errorln("Couldn't instantiate device : ", device1.DeviceId)
		return
	}

	time.Sleep(time.Duration(time.Second) * 3)

	node1.AddDevice(ctx, device1, logger)

	sensor1 := simulators.NewIoTSensorSim("sensor01", 3.9, 1.9, 5, 10, false)
	// sensor2 := simulators.NewIoTSensorSim("sensor02", 60.1, 3.0, 5, 9, true)
	// sensor3 := simulators.NewIoTSensorSim("sensor03", 38.6, 1.1, 5, 5, false)

	device1.AddSimulator(ctx, sensor1, logger).
		// AddSimulator(ctx, sensor2, logger).
		// AddSimulator(ctx, sensor3, logger).
		RunSimulators(logger).RunPublisher(ctx, logger)
	// RunSimulators(logger)

	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	// device1.RunPublisher(ctx, logger)

	fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	// device1.ShutdownSimulator("sensor01",logger)

	// time.Sleep(time.Duration(time.Second) * 10)

	// device2.AddSimulator(sensor2,logger)
	// device2.AddSimulator(sensor1,logger)

	// //

	// go func() {
	// 	for {
	// 		select {
	// 		case d := <-device1.Simulators[sensor1.SensorId].SensorData:
	// 			logger.WithField("Sensor Data ", d).Infoln("New data point from ", sensor1.SensorId)
	// 		case d := <-device1.Simulators[sensor2.SensorId].SensorData:
	// 			logger.WithField("Sensor Data ", d).Infoln("New data point from ", sensor2.SensorId)

	// 		}
	// 	}
	// }()

	// go func() {
	// 	for v := range device1.Simulators[sensor3.SensorId].SensorData {
	// 		fmt.Println(v)
	// 	}
	// }()

	// time.Sleep(time.Duration(time.Second) * 5)

	// device1.ShutdownSimulator("sensor03",logger)
	// fmt.Printf("device1.Simulators: %v\n", device1.Simulators)

	// time.Sleep(time.Duration(time.Second) * 3)

	// device1.AddSimulator(sensor3,logger)
	// device1.Simulators[sensor3.SensorId].Run(logger)

	// time.Sleep(time.Duration(time.Second) * 10)

	// fmt.Printf("device1.Simulators: %v\n", device1.Simulators)
	// fmt.Printf("device2.Simulators: %v\n", device2.Simulators)
	// fmt.Printf("sensor3: %v\n", sensor3)
	// for _, sim := range device1.Simulators {
	// 	sim.Shutdown <- true
	// }
	// time.Sleep(time.Duration(time.Second) * 1)

	// go func() {
	// 	for v := range device1.Simulators[sensor3.SensorId].SensorData {
	// 		logger.WithField("Sensor Data ", v).Infoln("New data point from ", sensor3.SensorId)
	// 	}
	// }()

	// time.Sleep(time.Duration(time.Second) * 10)
	// device1.ShutdownSimulator(ctx, sensor3.SensorId, logger).
	// 	ShutdownSimulator(ctx, sensor2.SensorId, logger).
	// 	ShutdownSimulator(ctx, sensor1.SensorId, logger)

	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	// time.Sleep(time.Duration(time.Second) * 3)
	// device1.ShutdownSimulator(sensor2.SensorId, logger)
	// time.Sleep(time.Duration(time.Second) * 3)
	// device1.ShutdownSimulator(sensor1.SensorId, logger)

	// time.Sleep(time.Duration(time.Second) * 5)
	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())
	// // node1.ShutdownDevice(ctx, device1.DeviceId, logger)
	// sensor1.Update <- simulators.UpdateSensorParams{
	// 	DelayMin:  1,
	// 	DelayMax:  1,
	// 	Randomize: false,
	// }
	// time.Sleep(time.Duration(time.Second) * 10)
	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())
	// sensor1.Update <- simulators.UpdateSensorParams{
	// 	DelayMin:  5,
	// 	DelayMax:  5,
	// 	Randomize: false,
	// }
	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	// device1, err = services.NewDeviceInstance(
	// 	ctx,
	// 	"spBv1.0",
	// 	"groupeId",
	// 	"node01",
	// 	"device01",
	// 	logger,
	// 	mqttConfig,
	// )

	// if err != nil {
	// 	logger.Errorln("Couldn't instantiate device : ", device1.DeviceId)
	// 	return
	// }

	// node1.AddDevice(device1, logger)

	// device1.AddSimulator(sensor1, logger).
	// 	AddSimulator(sensor2, logger).
	// 	AddSimulator(sensor3, logger).
	// 	RunSimulators(logger)

	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	// device1.RunPublisher(ctx, logger)

	// fmt.Printf("✅✅✅✅✅✅✅✅✅✅  runtime.NumGoroutine(): %v ✅✅✅✅✅✅✅✅✅✅\n", runtime.NumGoroutine())

	// node1.ShutdownDevice(device1.DeviceId, logger)

	// fmt.Printf("device1: %v\n", device1)
	// fmt.Printf("device1: %v\n", device1.SessionHandler.MqttClientOptions.ClientID)
	// device1.AddSimulator(sensor3, logger)
	// device1.RunSimulators(logger)
	// device1.RunPublisher(logger)

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig

}
