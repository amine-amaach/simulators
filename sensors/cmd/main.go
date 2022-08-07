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

	"github.com/amine-amaach/simulators/sensors/services"
	"github.com/awcullen/opcua/ua"
	"github.com/pkg/errors"
)

func main() {
	RANDOM_DELAY_BETWEEN_MESSAGES := true
	FIXED_DELAY_BETWEEN_MESSAGES := 5
	HOSTNAME, _ := os.Hostname()

	sensorSim := services.NewSensorSimService(HOSTNAME, 46010, []ua.UserNameIdentity{})
	dataGens := make(map[string]*services.DataGenService)

	// add namespace, save index for later
	nm := sensorSim.Srv.GetServer().NamespaceManager()
	nsi := nm.Add("http://github.com/amine-amaach/simulators/sensorsOPCUA")

	// sensorSim.Srv.GetServer().NamespaceManager().AddNode(ioTSensors)
	tempSensor := sensorSim.CreateNewVariableNode(nsi, "Temperature")
	sensorSim.AddVariableNode(tempSensor)

	dataGens["temperature"] = services.NewSensorService(20., 5.)

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

	simulator := func(ctx context.Context, sensor services.DataGenService, wg sync.WaitGroup) {
		randChannel := randIt(ctx)
		go func(sensor services.DataGenService) {
			defer wg.Done()
			val := sensor.CalculateNextValue()
			fmt.Println(val)
			t := time.Now().UTC()
			tempSensor.SetValue(ua.NewDataValue(val, 0, t, 0, t, 0))

			for {
				select {
				case <-randChannel:
					val = sensor.CalculateNextValue()
					fmt.Println(val)
					t = time.Now().UTC()
					tempSensor.SetValue(ua.NewDataValue(val, 0, t, 0, t, 0))
				case <-ctx.Done():
					return
				}
			}
		}(sensor)
	}

	for _, sensor := range dataGens {
		simulator(context.Background(), *sensor, wg)
	}

	// start server
	go func() {
		// start server
		log.Printf("Starting server '%s' at '%s'\n", sensorSim.Srv.GetServer().LocalDescription().ApplicationName.Text, sensorSim.Srv.GetServer().EndpointURL())
		if err := sensorSim.Srv.GetServer().ListenAndServe(); err != ua.BadServerHalted {
			log.Println(errors.Wrap(err, "Error starting server"))
		}
	}()

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
	log.Println("Stopping server...")
	sensorSim.Srv.GetServer().Close()

}
