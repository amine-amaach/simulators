package models

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
