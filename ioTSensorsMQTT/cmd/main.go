package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/amine-amaach/simulators/ioTSensorsMQTT/services"
	"github.com/amine-amaach/simulators/ioTSensorsMQTT/utils"
)

var (
	cfg     *utils.Config
	logger  *log.Logger
	mqttSvc *services.MQTTService
	sensors map[string]*services.SimulatorService
	wg      sync.WaitGroup
)

func init() {
	cfg = utils.GetConfig()
	logger = log.Default()
	mqttSvc = services.NewMQTTService()
	sensors = make(map[string]*services.SimulatorService, 0)
}

func main() {

	// Instantiate simulators
	for _, sensor := range cfg.SimParams {
		log.Println(utils.Colorize(fmt.Sprintf("%s IoT Sensor config found ⚙️", sensor.Name), utils.Blue))
		sensors[sensor.Name] = services.NewSensorService(sensor.Mean, sensor.StandardDeviation)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cm := mqttSvc.Connect(ctx, logger, cfg)

	// Setting up Random/Fixed delay between messages :
	wg = sync.WaitGroup{}
	wg.Add(len(cfg.SimParams))

	randIt := func(ctx context.Context) <-chan bool {
		randChannel := make(chan bool)
		go func(ctx context.Context) {
			delay := cfg.MQTTBroker.DelayBetweenMessages
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(delay) * time.Second):
					if cfg.MQTTBroker.RandomizeDelay {
						// if RANDOMIZE_DELAY_BETWEEN_MESSAGES set to true, randomize delay.
						delay = rand.Intn(cfg.MQTTBroker.DelayBetweenMessages) + rand.Intn(2)
						// fmt.Println("-----------------------> ", delay)
						randChannel <- true
					} else {
						randChannel <- true
					}
				}
			}
		}(ctx)
		return randChannel
	}

	simulator := func(ctx context.Context, topic string, sim *services.SimulatorService) {
		randChannel := randIt(ctx)
		go func(sim *services.SimulatorService) {
			defer wg.Done()

			mqttSvc.Publish(ctx, cm, cfg, logger, sim.CalculateNextValue(), topic)

			for {
				select {
				case <-randChannel:
					mqttSvc.Publish(ctx, cm, cfg, logger, sim.CalculateNextValue(), topic)
				case <-ctx.Done():
					return
				}
			}
		}(sim)
	}

	for name, sim := range sensors {
		simulator(ctx, fmt.Sprintf("%s/%s", cfg.MQTTBroker.RootTopic, name), sim)
	}

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig
	logger.Println(utils.Colorize("Signal caught ❌ Exiting...\n", utils.Magenta))
	cancel()

	wg.Wait()
	logger.Println(utils.Colorize("Shutdown complete ✅", utils.Green))
}
