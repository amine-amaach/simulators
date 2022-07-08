package main

import (
	"context"
	"encoding/json"

	"github.com/amine-amaach/simulators/services"
	"github.com/amine-amaach/simulators/services/models"
	"github.com/amine-amaach/simulators/utils"
)

func main() {
	// Load Configuration
	cfg := utils.NewConfig(utils.NewLogger())
	svc := services.NewMqttService()
	cm, cancel, _ := svc.Connect(context.Background(), utils.NewLogger(), *cfg)
	payload := models.Generator{Lon: 12.32, GeneratorID: "HJHSSMDSJDSKD"}
	bytes, _ := json.Marshal(payload)
	svc.Publish(context.Background(), cm, utils.NewLogger(), "Gen/", bytes, 0, false)
	svc.Close(cancel, utils.NewLogger())
}
