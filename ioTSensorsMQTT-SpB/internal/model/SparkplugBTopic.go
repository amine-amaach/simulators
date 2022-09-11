package model

// sparkplug-B message types
const (
	NodeBirth     string = "NBIRTH"
	NodeDeath     string = "NDEATH"
	NodeData      string = "NDATA"
	NodeCommand   string = "NCMD"
	DeviceBirth   string = "DBIRTH"
	DeviceDeath   string = "DDEATH"
	DeviceData    string = "DDATA"
	DeviceCommand string = "DCMD"
)

type SparkplugBTopic struct {
	Namespace   string
	GroupId     string
	EdgeNodeId  string
	DeviceId    string
	MessageType string
}

func NewSparkplugBTopic(topic *SparkplugBTopic) string {
	return topic.Namespace + "/" + topic.GroupId + "/" + topic.MessageType + "/" + topic.EdgeNodeId + "/" + topic.DeviceId
}
