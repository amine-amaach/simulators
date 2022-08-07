package services

import (
	"math"
	"math/rand"
	"time"
)

type SensorService struct {
	// sensor data mean value
	mean float64
	// sensor data standard deviation value
	standardDeviation float64
	// stepSizeFactor is used when calculating the next value.
	stepSizeFactor float64
	// sensor data current value
	value float64
}

func NewSensorService(mean, standardDeviation float64) *SensorService {
	rand.Seed(time.Now().UnixNano())
	return &SensorService{
		mean:              mean,
		standardDeviation: math.Abs(standardDeviation),
		stepSizeFactor:    math.Abs(standardDeviation) / 10,
		value:             mean - rand.Float64(),
	}
}

func (sensor *SensorService) CalculateNextValue() float64 {
	// first calculate how much the value will be changed
	valueChange := rand.Float64() * sensor.stepSizeFactor
	// second decide if the value is increased or decreased
	factor := sensor.DecideFactor()
	// apply valueChange and factor to value and return
	sensor.value += valueChange * factor
	return sensor.value
}

func (sensor SensorService) DecideFactor() float64 {
	var (
		continueDirection, changeDirection float64
		distance                           float64 // the distance from the mean.
	)
	// depending on if the current value is smaller or bigger than the mean
	// the direction changes.
	if sensor.value > sensor.mean {
		distance = sensor.value - sensor.mean
		continueDirection = 1
		changeDirection = -1
	} else {
		distance = sensor.mean - sensor.value
		continueDirection = -1
		changeDirection = 1
	}
	// the chance is calculated by taking half of the standardDeviation
	// and subtracting the distance divided by 50. This is done because
	// chance with a distance of zero would mean a 50/50 chance for the
	// randomValue to be higher or lower.
	// The division by 50 was found by empiric testing different values.
	chance := (sensor.standardDeviation / 2) - (distance / 50)
	randomValue := sensor.standardDeviation * rand.Float64()
	// if the random value is smaller than the chance we continue in the
	// current direction if not we change the direction.
	if randomValue < chance {
		return continueDirection
	}
	return changeDirection
}
