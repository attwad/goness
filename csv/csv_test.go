package csv

import (
	"testing"
)

func TestParseFile(t *testing.T) {
	results, err := ParseFile("test_scan_900z53.csv")
	if err != nil {
		t.Error(err)
	}
	if len(results) != 46 {
		t.Errorf("Should have parsed 46 records, was %v", len(results))
	}
}

func TestParseFileDoesNotExists(t *testing.T) {
	_, err := ParseFile("nosuchfilehere")
	if err == nil {
		t.Error("Should have thrown an error due to missing file")
	}
}
