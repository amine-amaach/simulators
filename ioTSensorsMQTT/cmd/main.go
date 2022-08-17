package main

import (
	"context"
	"log"

	"github.com/amine-amaach/simulators/ioTSensorsMQTT/services"
	"github.com/amine-amaach/simulators/ioTSensorsMQTT/utils"
)

var (
	cfg     *utils.Config
	logger  *log.Logger
	mqttSvc *services.MQTTService
)

func init() {
	cfg = utils.GetConfig()
	logger = log.Default()
	mqttSvc = services.NewMQTTService()
}

func main() {
	simSvc := services.NewSensorService(35.5, 7.3)

	// fmt.Println(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm := mqttSvc.Connect(ctx, logger, cfg)

	mqttSvc.Publish(ctx,cm,cfg, logger, simSvc.CalculateNextValue(), "IoTSensorsMQTT/Temperature")
	
	mqttSvc.Close(cancel, logger)

}
