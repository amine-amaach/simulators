package simulators

import (
	"math"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
)

type IoTSensorSim struct {
	// Sensor Id
	SensorId string
	// sensor data mean value
	mean float64
	// sensor data standard deviation value
	standardDeviation float64
	// sensor data current value
	currentValue float64

	// Delay between each data point
	DelayMin uint32
	DelayMax uint32
	// Randomize delay between data points if true,
	// otherwise DelayMin will be set as fixed delay
	Randomize bool

	// Channel to send data to device
	SensorData chan float64
	// Shutdown the sensor
	Shutdown chan bool

	// Check if it's running
	IsRunning bool

	// Sensor Alias, to be used in DDATA, instead of name
	Alias uint64

	// Check if it's already assigned to a device,
	// it's only allowed to be be assigned to one device
	IsAssigned *bool

	// Used to Update sensor parameters at runtime
	Update chan UpdateSensorParams
}

type UpdateSensorParams struct {
	// Delay between each data point
	DelayMin uint32
	DelayMax uint32
	// Randomize delay between data points if true,
	// otherwise DelayMin will be set as fixed delay
	Randomize bool
}

func NewIoTSensorSim(
	id string,
	mean,
	standardDeviation float64,
	DelayMin uint32,
	DelayMax uint32,
	Randomize bool,
) *IoTSensorSim {
	rand.Seed(time.Now().UnixNano())
	isAssigned := false
	alias := 100 + uint64(rand.Int63n(10000))
	return &IoTSensorSim{
		SensorId:          id,
		mean:              mean,
		standardDeviation: math.Abs(standardDeviation),
		currentValue:      mean - rand.Float64(),
		IsRunning:         false,
		IsAssigned:        &isAssigned,
		SensorData:        make(chan float64),
		// Add a buffered channel with capacity 1
		// to send a shutdown signal from the device.
		Shutdown:  make(chan bool, 1),
		DelayMin:  DelayMin,
		DelayMax:  DelayMax,
		Randomize: Randomize,
		Alias:     alias,
		Update:    make(chan UpdateSensorParams, 1),
	}
}

func (s *IoTSensorSim) calculateNextValue() float64 {
	// first calculate how much the value will be changed
	valueChange := rand.Float64() * math.Abs(s.standardDeviation) / 10
	// second decide if the value is increased or decreased
	factor := s.decideFactor()
	// apply valueChange and factor to value and return
	s.currentValue += valueChange * factor
	return s.currentValue
}

func (s *IoTSensorSim) decideFactor() float64 {
	var (
		continueDirection, changeDirection float64
		distance                           float64 // the distance from the mean.
	)
	// depending on if the current value is smaller or bigger than the mean
	// the direction changes.
	if s.currentValue > s.mean {
		distance = s.currentValue - s.mean
		continueDirection = 1
		changeDirection = -1
	} else {
		distance = s.mean - s.currentValue
		continueDirection = -1
		changeDirection = 1
	}
	// the chance is calculated by taking half of the standardDeviation
	// and subtracting the distance divided by 50. This is done because
	// chance with a distance of zero would mean a 50/50 chance for the
	// randomValue to be higher or lower.
	// The division by 50 was found by empiric testing different values.
	chance := (s.standardDeviation / 2) - (distance / 50)
	randomValue := s.standardDeviation * rand.Float64()
	// if the random value is smaller than the chance we continue in the
	// current direction if not we change the direction.
	if randomValue < chance {
		return continueDirection
	}
	return changeDirection
}

func (s *IoTSensorSim) Run(log *logrus.Logger) {
	if s.IsRunning {
		log.WithField("Senor Id", s.SensorId).Debugln("Already running 🔔")
		return
	}

	s.IsRunning = true
	if s.DelayMin <= 0 {
		s.DelayMin = 1
	} else if s.DelayMin > s.DelayMax && s.Randomize {
		s.DelayMax = s.DelayMin
	}

	go func() {
		delay := s.DelayMin
		log.WithField("Senor Id", s.SensorId).Debugln("Started running 🔔")
		s.SensorData <- s.calculateNextValue()
		for {
			select {
			case _, open := <-s.Shutdown:
				log.WithField("Senor Id", s.SensorId).Debugln("Got shutdown signal 🔔")
				s.IsRunning = false
				if open {
					// Send signal to publisher to shutdown
					s.Shutdown <- true
				}
				return
			case <-time.After(time.Duration(delay) * time.Second):
				if s.Randomize {
					// log.WithField("Previous Delay :", delay).Warnln("🔔🔔")
					delay = uint32(rand.Intn(int(s.DelayMax-s.DelayMin))) + s.DelayMin
					// log.WithField("Next Delay :", delay).Infoln("🔔🔔")
				}
				s.SensorData <- s.calculateNextValue()
			case newParams := <-s.Update:
				if newParams.DelayMin > 0 && !(newParams.DelayMin > newParams.DelayMax && newParams.Randomize) {
					s.DelayMax = newParams.DelayMax
					s.DelayMin = newParams.DelayMin
					s.Randomize = newParams.Randomize
					delay = newParams.DelayMin
					log.WithFields(logrus.Fields{
						"Senor Id":  s.SensorId,
						"Min delay": newParams.DelayMin,
						"Max delay": newParams.DelayMax,
						"Randomize": newParams.Randomize,
					}).Debugln("Got updated parameters, sensor updated 🔔")
				} else {
					log.WithFields(logrus.Fields{
						"Senor Id":  s.SensorId,
						"Min delay": newParams.DelayMin,
						"Max delay": newParams.DelayMax,
						"Randomize": newParams.Randomize,
					}).Debugln("Wrong parameters, not updating sensor 🔔")
				}
			}
		}
	}()

}
