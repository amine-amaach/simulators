package ports

import (
	"context"

	"github.com/amine-amaach/simulators/pgmqtt/models"
	"github.com/amine-amaach/simulators/pgmqtt/utils"
	"github.com/eclipse/paho.golang/autopaho"
	"go.uber.org/zap"
)

type MqttPort interface {
	ConnectConnect(ctx context.Context, logger *zap.SugaredLogger, cfg utils.Config) (*autopaho.ConnectionManager, context.CancelFunc, error)
	Close(cancel context.CancelFunc, logger *zap.SugaredLogger)
	Publish(ctx context.Context, cm *autopaho.ConnectionManager, logger *zap.SugaredLogger, topic string, payload models.Message, qos byte, retain bool)
}
