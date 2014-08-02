package xml

import (
	"testing"
)

func TestParseFile(t *testing.T) {
	result, err := ParseFile("test_scan_gipz4m.nessus")
	if err != nil {
		t.Error(err)
	}
	if result.Policy.Name != "basic network scan policy" {
		t.Errorf("Policy name should be %v, was %v", "basic network scan policy", result.Policy.Name)
	}
	if len(result.Report.ReportHosts) != 4 {
		t.Errorf("Report should have parsed 4 hosts, was %v", len(result.Report.ReportHosts))
	}
}

func TestParseFileDoesNotExists(t *testing.T) {
	_, err := ParseFile("nosuchfilehere")
	if err == nil {
		t.Error("Should have thrown an error due to missing file")
	}
}
