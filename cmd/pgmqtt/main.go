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
	"go.uber.org/zap"
)

var (
	// Viper Config used to handle config files and env variables.
	cfg *utils.Config
	// Zap logger used for logging.
	logger *zap.SugaredLogger
)

func init() {

	// Set random source for math/rand generator
	rand.Seed(time.Now().UnixNano())

	// Instantiate a Zap logger.
	logger = utils.NewLogger()
	defer logger.Sync()

	// Instantiate a Viper Config wired with the Zap logger.
	cfg = utils.NewConfig(logger)

	// Make sure not to exceed the generator limit number.
	if cfg.GeneratorsNumber > cfg.GeneratorsLimitNumber {
		cfg.GeneratorsNumber = cfg.GeneratorsLimitNumber
	}
}

func main() {
	fmt.Println(cfg.RandomDelayBetweenMessages, cfg.DelayBetweenMessagesMin)

	ctx, cancel := context.WithCancel(context.Background())

	mqttService := services.NewMqttService()
	cm := mqttService.Connect(ctx, logger, cfg)

	pGenerators := make([]models.Generator, cfg.GeneratorsNumber)

	pgService := services.NewService(pGenerators, cfg, cfg.GeneratorsNumber)

	simService := services.NewSimService()

	//
	// Handle Random delay between messages :
	//
	wg := sync.WaitGroup{}
	wg.Add(cfg.GeneratorsNumber)

	randIt := func(ctx context.Context) <-chan float64 {
		randChannel := make(chan float64)
		go func(ctx context.Context) {
			// Set the default delay if RANDOM_DELAY_BETWEEN_MESSAGES == false
			// to DelayBetweenMessagesMin.
			r := float64(cfg.DelayBetweenMessagesMin)
			for {
				select {
				case <-ctx.Done():
					return // returning not to leak the goroutine
				case <-time.After(time.Duration(r) * time.Second): // update the delay
					// If RANDOM_DELAY_BETWEEN_MESSAGES == true set the delayBetweenMessages between the messages randomly.
					if cfg.RandomDelayBetweenMessages {
						r = rand.Float64() * float64(cfg.DelayBetweenMessagesMax)
						randChannel <- r
					} else {
						r = float64(cfg.DelayBetweenMessagesMin)
						randChannel <- r
					}

				}
			}
		}(ctx)
		return randChannel
	}

	simulator := func(pg models.Generator, wg sync.WaitGroup) {
		// Set the delay for each pg.
		randChannel := randIt(ctx)
		go func(pg models.Generator) {
			defer wg.Done()

			mqttService.Publish(ctx, cm, logger, pgService.BuildPGMessagePayloads(simService, &pg, logger), 0, false)
			mqttService.Publish(ctx, cm, logger, pgService.Update(simService, &pg, logger), 0, false)

			for {
				select {
				case <-randChannel:
					mqttService.Publish(ctx, cm, logger, pgService.Update(simService, &pg, logger), 0, false)
				case <-ctx.Done():
					logger.Infof(utils.Colorize(fmt.Sprintf("publisher done for [%s] : %s ✖️", pg.GeneratorTopic, ctx.Err()), utils.Cyan))
					return
				}
			}
		}(pg)
	}

	for _, pg := range pGenerators {
		simulator(pg, wg)
	}

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig
	mqttService.Close(cancel, logger)
	time.Sleep(900) // Just to show the last logs
	logger.Warn(utils.Colorize("Signal caught ❌ Exiting...", utils.Magenta))
}
