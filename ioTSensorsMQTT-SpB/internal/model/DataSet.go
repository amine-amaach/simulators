package model

type DataSet struct {
	// The number of columns
	NumOfColumns uint64 `json:"num_of_columns,omitempty"`

	// A list containing the names of each column
	ColumnNames []string `json:"column_names,omitempty"`

	// A list containing the data types of each column
	Types []string `json:"types,omitempty"`

	// A list containing the rows in the data set
	Rows []Row `json:"rows,omitempty"`
}
