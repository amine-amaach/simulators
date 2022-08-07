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

	"github.com/amine-amaach/simulators/sensors/services"
)

func main() {
	RANDOM_DELAY_BETWEEN_MESSAGES := true
	FIXED_DELAY_BETWEEN_MESSAGES := 5

	sensors := make(map[string]*services.SensorService)

	sensors["temperature"] = services.NewSensorService(20., 5.)
	sensors["pressure"] = services.NewSensorService(50., 3.5)

	// Setting up Random/Fixed delay between messages :
	wg := sync.WaitGroup{}
	wg.Add(1)

	randIt := func(ctx context.Context) <-chan bool {
		randChannel := make(chan bool)
		go func(ctx context.Context) {
			delay := FIXED_DELAY_BETWEEN_MESSAGES
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(delay) * time.Second):
					if RANDOM_DELAY_BETWEEN_MESSAGES {
						// if RANDOM_DELAY_BETWEEN_MESSAGES set to true, randomize delay.
						delay = rand.Intn(FIXED_DELAY_BETWEEN_MESSAGES) + rand.Intn(2)
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

	simulator := func(ctx context.Context, sensor services.SensorService, wg sync.WaitGroup) {
		randChannel := randIt(ctx)
		go func(sensor services.SensorService) {
			defer wg.Done()
			fmt.Println(sensor.CalculateNextValue())

			for {
				select {
				case <-randChannel:
					fmt.Println(sensor.CalculateNextValue())
				case <-ctx.Done():
					return
				}
			}
		}(sensor)
	}

	for _, sensor := range sensors {
		simulator(context.Background(), *sensor, wg)
	}

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
	fmt.Println("Exiting...")

}
