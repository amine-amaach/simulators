package main

import (
	"context"
	"fmt"
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

	ctx, cancel := context.WithCancel(context.Background())

	logger := utils.NewLogger()
	defer logger.Sync()

	cfg := utils.NewConfig(logger)

	mqttService := services.NewMqttService()
	cm := mqttService.Connect(ctx, logger, cfg)

	pGenerators := make([]models.Generator, cfg.GeneratorsNumber)

	pgService := services.NewService(pGenerators, cfg, cfg.GeneratorsNumber)

	simService := services.NewSimService()

	simulator := func(pg models.Generator, wg sync.WaitGroup) {
		go func(pg models.Generator) {
			defer wg.Done()

			mqttService.Publish(ctx, cm, logger, pgService.BuildPGMessagePayloads(simService, &pg, logger), 0, false)
			mqttService.Publish(ctx, cm, logger, pgService.Update(simService, &pg, logger), 0, false)

			for {
				select {
				case <-time.After(time.Duration(cfg.DelayBetweenMessagesMin) * time.Second):
					mqttService.Publish(ctx, cm, logger, pgService.Update(simService, &pg, logger), 0, false)
				case <-ctx.Done():
					logger.Warnf(utils.Colorize(fmt.Sprintf("publisher done for [%s] : %s ✖️", pg.GeneratorTopic, ctx.Err()), utils.Cyan))
					return
				}
			}
		}(pg)
	}

	wg := sync.WaitGroup{}
	wg.Add(cfg.GeneratorsNumber)

	for _, pg := range pGenerators {
		simulator(pg, wg)
	}

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig
	mqttService.Close(cancel, logger)
	logger.Warn(utils.Colorize("Signal caught ❌ Exiting...", utils.Magenta))
}
