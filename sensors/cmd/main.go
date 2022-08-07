package main

import (
	"fmt"

	"github.com/amine-amaach/simulators/sensors/services"
)

func main() {
	sensor := services.NewSensorService(20., 5.)
	for i := 0; i < 5000; i++ {
		fmt.Println(sensor.CalculateNextValue())
	}
}
