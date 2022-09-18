package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/component"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/log"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/services"
	"github.com/amineamaach/simulators/iotSensorsMQTT-SpB/internal/simulators"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// go services.NewMonitor(2)

	// TODO ::
	// Each device with a unique context/ same for node
	//

	logger := log.NewLogger()
	// logger.SetLevel(logrus.InfoLevel)

	mqttConfig := component.NewMQTTConfig()
	mqttConfig.ConnectTimeout = "10s"
	mqttConfig.KeepAlive = 10
	mqttConfig.QoS = 1
	mqttConfig.ConnectRetry = 10
	mqttConfig.CleanStart = true
	mqttConfig.SessionExpiryInterval = 30
	// mqttConfig.URL = "tcp://broker.hivemq.com:1883"
	mqttConfig.URL = "tcp://broker.emqx.io:1883"
	// mqttConfig.URL = "tcp://test.mosquitto.org:1883"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node1, err := services.NewEdgeNodeInstance(
		ctx,
		"spBv1.0",
		"IoTSensors",
		"SparkplugB",
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
		"IoTSensors",
		"SparkplugB",
		"emulatedDevice",
		logger,
		mqttConfig,
		10,
		true,
	)

	// time.Sleep(time.Second*time.Duration(2))
	device1.SessionHandler.MqttClient.AwaitConnection(ctx)

	if err != nil {
		logger.Errorln("Couldn't instantiate device : ", device1.DeviceId)
		return
	}

	node1.AddDevice(ctx, device1, logger)

	sensor1 := simulators.NewIoTSensorSim("sensor01", 3.9, 1.9, 2, 10, false)
	device1 = device1.AddSimulator(ctx, sensor1, logger)
	sensor2 := simulators.NewIoTSensorSim("sensor02", 60.1, 3.0, 2, 9, true)
	device1 = device1.AddSimulator(ctx, sensor2, logger)
	sensor3 := simulators.NewIoTSensorSim("sensor03", 38.6, 1.1, 3, 5, false)
	device1 = device1.AddSimulator(ctx, sensor2, logger)
	sensor4 := simulators.NewIoTSensorSim("sensor04", 38.6, 1.1, 3, 5, false)
	device1 = device1.AddSimulator(ctx, sensor4, logger)
	sensor5 := simulators.NewIoTSensorSim("sensor05", 38.6, 1.1, 3, 5, false)
	device1 = device1.AddSimulator(ctx, sensor5, logger)
	sensor6 := simulators.NewIoTSensorSim("sensor06", 38.6, 1.1, 3, 5, false)
	device1 = device1.AddSimulator(ctx, sensor6, logger)

	device1.AddSimulator(ctx, sensor3, logger).RunSimulators(logger).RunPublisher(ctx, logger)
	// sensor4 := simulators.NewIoTSensorSim("sensor04", 38.6, 1.1, 5, 5, false)
	// // sensor5 := simulators.NewIoTSensorSim("sensor05", 38.6, 1.1, 1, 5, false)

	// device1 = device1.AddSimulator(ctx, sensor4, logger)

	// 	// AddSimulator(ctx, sensor5, logger).

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":8080", nil)

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig

	// We could cancel the context at this point but will call Disconnect instead (this waits for autopaho to shutdown)
	// ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	// defer cancel()
	// _ = node1.SessionHandler.MqttClient.Disconnect(ctx)
	// _ = device1.SessionHandler.MqttClient.Disconnect(ctx)

	// fmt.Println("shutdown complete")

}
