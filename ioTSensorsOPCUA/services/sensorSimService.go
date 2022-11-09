package services

import (
	"fmt"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

type SensorSimService struct {
	host    string
	port    int
	userIds []ua.UserNameIdentity
	Srv     *UaSrvService
}

func NewSensorSimService(host string, port int, userIds []ua.UserNameIdentity, additionalHosts *[]string) *SensorSimService {
	return &SensorSimService{
		host:    host,
		port:    port,
		userIds: userIds,
		Srv:     NewUaSrvService(host, port, userIds, additionalHosts),
	}
}

func (sensorSim SensorSimService) CreateNewVariableNode(nsi uint16, nodeName string) *server.VariableNode {
	return server.NewVariableNode(
		ua.NodeIDString{NamespaceIndex: nsi, ID: nodeName},
		ua.QualifiedName{NamespaceIndex: nsi, Name: nodeName},
		ua.LocalizedText{Text: nodeName},
		ua.LocalizedText{Text: fmt.Sprint(nodeName, " IoT Sensor Simulator")},
		nil,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.NodeIDString{NamespaceIndex: nsi, ID: "IoTSensors"}},
			},
		},
		ua.DataValue{},
		ua.DataTypeIDDouble,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsHistoryRead,
		250.0,
		false,
		sensorSim.Srv.server.Historian(),
	)
}

func (sensorSim SensorSimService) AddVariableNode(node server.Node) {
	sensorSim.Srv.server.NamespaceManager().AddNode(node)
}
