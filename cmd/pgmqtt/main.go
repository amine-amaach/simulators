package main

import (
	"context"
	"math/rand"
	"time"

	"github.com/amine-amaach/simulators/services"
	"github.com/amine-amaach/simulators/services/models"
	"github.com/amine-amaach/simulators/utils"
)

func main() {
	// Set random source for math/rand generator
	rand.Seed(time.Now().UnixNano())

	ctx := context.Background()

	logger := utils.NewLogger()

	cfg := utils.NewConfig(logger)

	svc := services.NewMqttService()
	cm, cancel, _ := svc.Connect(context.Background(), utils.NewLogger(), *cfg)

	pGenerators := make([]models.Generator, 1)

	pgService := services.NewService(pGenerators, cfg, 1)

	simSvc := services.NewSimService()

	svc.Publish(ctx, cm, logger, pgService.BuildMessagePayloads(simSvc, &pGenerators[0], logger), 0, false)
	svc.Close(cancel, utils.NewLogger())
}
