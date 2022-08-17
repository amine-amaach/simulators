package main

import (
	"fmt"

	"github.com/amine-amaach/simulators/ioTSensorsMQTT/utils"
)

var (
	cfg *utils.Config
)

func init()  {
	cfg = utils.GetConfig()
}

func main() {
	// simSrv := services.NewSensorService(35.5, 7.3)

	

	fmt.Println(cfg)

}
