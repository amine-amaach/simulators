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

	"github.com/amine-amaach/simulators/ioTSensorsOPCUA/services"
	"github.com/amine-amaach/simulators/ioTSensorsOPCUA/utils"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"github.com/pkg/errors"
)

type sensor struct {
	sensorNode *server.VariableNode
	dataGen    *services.DataGenService
}

type params struct {
	name              string
	mean              float64
	standardDeviation float64
}

func main() {
	version := "v1.0.0"
	website := "https://www.linkedin.com/in/amine-amaach/"
	banner := `
 ___    _____   ____                                   ___  ____   ____ _   _   _    
|_ _|__|_   _| / ___|  ___ _ __  ___  ___  _ __ ___   / _ \|  _ \ / ___| | | | / \   %s
 | |/ _ \| |   \___ \ / _ \ '_ \/ __|/ _ \| '__/ __| | | | | |_) | |   | | | |/ _ \  
 | | (_) | |    ___) |  __/ | | \__ \ (_) | |  \__ \ | |_| |  __/| |___| |_| / ___ \ 
|___\___/|_|   |____/ \___|_| |_|___/\___/|_|  |___/  \___/|_|    \____|\___/_/   \_\
IoT Sensors Data Over OPCUA
______________________________________________________________________________O/__________
%s                                     O\           
`
	// Print Banner
	fmt.Println(utils.Colorize(fmt.Sprintf(banner, version, website), utils.Cyan))

	// Getting configs from the file
	configs := utils.GetConfig()

	// Set Users credentials
	USERIDs := []ua.UserNameIdentity{}
	for _, v := range configs.UserIds {
		USERIDs = append(USERIDs, ua.UserNameIdentity{UserName: v.Username, Password: v.Password})
	}

	// Initiate a sensor simulator service
	// create new variable hn, which equals to configs.Host
	hn := configs.Host
	sensorSim := services.NewSensorSimService(hn, 46010, USERIDs, &configs.Certificate)
	nm := sensorSim.Srv.GetServer().NamespaceManager()
	nsi := nm.Add("http://github.com/amine-amaach/simulators/ioTSensorsOPCUA")

	// start server
	go func() {
		desc := utils.Colorize(sensorSim.Srv.GetServer().LocalDescription().ApplicationName.Text, utils.Magenta)
		endpoint := utils.Colorize(sensorSim.Srv.GetServer().EndpointURL(), utils.Cyan)
		log.Printf("%s '%s' at '%s'\n", utils.Colorize("Starting server ", utils.Cyan), desc, endpoint)
		log.Printf("Hostname: %s", hn)
		err := sensorSim.Srv.GetServer().ListenAndServe()
		if err != ua.BadServerHalted {
			log.Println(errors.Wrap(err, "Error starting server"))
		}
	}()

	// Create a map for the IoT sensors
	sensors := make(map[string]sensor)

	sensorParams := make([]params, 0)
	for _, param := range configs.SimulatorsParams {
		log.Println(utils.Colorize(fmt.Sprintf("%s IoT Sensor config found ⚙️", param.Name), utils.Blue))
		sensorParams = addSensorParam(sensorParams, param.Name, param.Mean, param.StandardDeviation)
	}

	// Add sensors as configured in the config file
	for _, sen := range sensorParams {
		sensors[sen.name] = sensor{
			sensorNode: sensorSim.CreateNewVariableNode(nsi, sen.name),
			dataGen:    services.NewSensorService(sen.mean, sen.standardDeviation),
		}
		sensorSim.AddVariableNode(sensors[sen.name].sensorNode)
	}

	// Setting up Random/Fixed delay between messages :
	wg := sync.WaitGroup{}
	wg.Add(1)

	randIt := func(ctx context.Context) <-chan bool {
		randChannel := make(chan bool)
		go func(ctx context.Context) {
			delay := configs.SET_DELAY_BETWEEN_MESSAGES
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(delay) * time.Second):
					if configs.RANDOMIZE_DELAY_BETWEEN_MESSAGES {
						// if RANDOMIZE_DELAY_BETWEEN_MESSAGES set to true, randomize delay.
						delay = rand.Intn(configs.SET_DELAY_BETWEEN_MESSAGES) + rand.Intn(2)
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

	simulator := func(ctx context.Context, sen sensor, wg *sync.WaitGroup) {
		randChannel := randIt(ctx)
		go func(sen sensor) {
			defer wg.Done()

			t := time.Now().UTC()
			sen.sensorNode.SetValue(ua.NewDataValue(sen.dataGen.CalculateNextValue(), 0, t, 0, t, 0))

			for {
				select {
				case <-randChannel:
					t = time.Now().UTC()
					sen.sensorNode.SetValue(ua.NewDataValue(sen.dataGen.CalculateNextValue(), 0, t, 0, t, 0))
				case <-ctx.Done():
					return
				}
			}
		}(sen)
	}

	for key, sen := range sensors {
		simulator(context.Background(), sen, &wg)
		log.Println(utils.Colorize(fmt.Sprintf("🏷️  Publishing %s IoT sensor data ...", key), utils.Green))
	}

	// Wait for a signal before exiting
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	<-sig
	log.Println("Stopping server...")
	sensorSim.Srv.GetServer().Close()

}

func addSensorParam(sensorParams []params, name string, mean, stdDev float64) []params {
	return append(sensorParams, params{
		name:              name,
		mean:              mean,
		standardDeviation: stdDev,
	})
}
