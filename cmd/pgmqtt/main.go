package main

import (
	"context"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
	defer logger.Sync()

	cfg := utils.NewConfig(logger)

	mqttService := services.NewMqttService()
	cm, err := mqttService.Connect(ctx, logger, cfg)

	pGenerators := make([]models.Generator, cfg.GeneratorsNumber)

	pgService := services.NewService(pGenerators, cfg, cfg.GeneratorsNumber)

	simService := services.NewSimService()

	var wg sync.WaitGroup
	wg.Add(cfg.GeneratorsNumber)

	for _, pg := range pGenerators {
		go func(pg models.Generator) {
			defer wg.Done()

			mqttService.Publish(ctx, cm, logger, pgService.BuildPGMessagePayloads(simService, &pg, logger), 0, false)
			mqttService.Publish(ctx, cm, logger, pgService.Update(simService, &pg, logger), 0, false)

			for {
				if cm.AwaitConnection(ctx) != nil { // Should only happen when context is cancelled
					logger.Warnf("publisher done (AwaitConnection: %s) ✖️", err.Error())
					return
				}

				select {
				case <-time.After(time.Duration(cfg.DelayBetweenMessagesMin) * time.Second):
					mqttService.Publish(ctx, cm, logger, pgService.Update(simService, &pg, logger), 0, false)
				case <-ctx.Done():
					logger.Warnf("publisher done : %s ✖️", ctx.Err())
					return
				}
			}
		}(pg)

	}

	time.Sleep(time.Second * 6)
	mqttService.Close(ctx, logger)

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig
	mqttService.Close(ctx, logger)
	logger.Warn(utils.Colorize("Signal caught ❌ Exiting...", utils.Magenta))
}
