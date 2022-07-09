package models

import "time"

type Message struct {
	ItemTopic         string      `json:"ItemTopic"`
	ItemId            string      `json:"ItemId"`
	ItemName          string      `json:"ItemName"`
	ItemValue         interface{} `json:"ItemValue"`
	ItemOldValue      interface{} `json:"ItemOldValue"`
	ItemDataType      string      `json:"ItemDataType"`
	ChangedTimestamp  string      `json:"ChangedTimestamp"`
	PreviousTimestamp string      `json:"PreviousTimestamp"`
}

func NewMessage(value interface{}, name string, id string, datType string) Message {
	return Message{
		ItemValue:         value,
		ItemName:          name,
		ItemId:            id,
		ItemDataType:      datType,
		ChangedTimestamp:  time.Now().Format(time.RFC3339),
		PreviousTimestamp: time.Now().Format(time.RFC3339),
	}

}
