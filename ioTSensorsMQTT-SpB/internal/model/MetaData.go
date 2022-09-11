package model

import sparkplug "github.com/amineamaach/simulators/iotSensorsMQTT-SpB/third_party/sparkplug_b"

type MetaData struct {
	// Indicates if the metric represents one of multiple parts.
	IsMultipart bool `json:"is_multipart,omitempty"`

	// A content type associated with the metric.
	ContentType string `json:"content_type,omitempty"`

	// A size associated with the metric.
	Size uint64 `json:"size,omitempty"`

	// A sequence associated with the metric.
	Seq uint64 `json:"seq,omitempty"`

	// A file name associated with the metric.
	FileName string `json:"file_name,omitempty"`

	// A file type associated with the metric.
	FileType string `json:"file_type,omitempty"`

	// A MD5 sum associated with the metric.
	Md5 string `json:"md_5,omitempty"`

	// A description associated with the metric.
	Description string `json:"description,omitempty"`
}


func (meta *MetaData) ConvertMetaData(protoMetric *sparkplug.Payload_Metric) {
	protoMetric.Metadata.IsMultiPart = &meta.IsMultipart
	protoMetric.Metadata.ContentType = &meta.ContentType
	protoMetric.Metadata.Size = &meta.Size
	protoMetric.Metadata.Seq = &meta.Seq
	protoMetric.Metadata.FileName = &meta.FileName
	protoMetric.Metadata.FileType = &meta.FileType
	protoMetric.Metadata.Md5 = &meta.Md5
	protoMetric.Metadata.Description = &meta.Description
}