// Package csv provides parsing for nessus CSV reports into Go structures.
package csv

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Record is a Go structure representing a single report in a csv nessus file.
type Record struct {
	PluginID     string
	CVE          []string
	CVSS         string
	Risk         string
	Host         string
	Protocol     string
	Port         int64
	Name         string
	Synopsis     string
	Description  string
	Solution     string
	SeeAlso      []string
	PluginOutput string
}

func newRecord(csvRec []string) (*Record, error) {
	rec := new(Record)
	if len(csvRec) != 13 {
		return nil, fmt.Errorf("Unexpected length of record: %d (expected 13)", len(csvRec))
	}
	rec.PluginID = csvRec[0]
	rec.CVE = strings.Split(csvRec[1], "\n")
	rec.CVSS = csvRec[2]
	rec.Risk = csvRec[3]
	rec.Host = csvRec[4]
	rec.Protocol = csvRec[5]
	port, err := strconv.ParseInt(csvRec[6], 10, 64)
	if err != nil {
		return nil, err
	}
	rec.Port = port
	rec.Name = csvRec[6]
	rec.Synopsis = csvRec[7]
	rec.Description = csvRec[8]
	rec.Solution = csvRec[9]
	rec.SeeAlso = strings.Split(csvRec[10], "\n")
	return rec, nil
}

// ParseFile parses a nessus report csv file and outputs the corresponding list of Records.
func ParseFile(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	// Ignore the first line.
	_, err = reader.Read()
	records := make([]Record, 1)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
			return nil, err
		}
		rec, err := newRecord(record)
		if err != nil {
			fmt.Println(err)
			continue
		}
		records = append(records, *rec)
	}
	return records, nil
}

/*
func main() {
	records, err := ParseFile("test_scan_900z53.csv")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(records)
}
*/
