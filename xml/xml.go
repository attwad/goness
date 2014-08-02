// Package xml provides parsing for nessus XML reports into Go structures.
package xml

import (
	"encoding/xml"
	"os"
)

// Preference is a single preference contained in a policy.
type Preference struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}
type ServerPreferences struct {
	Preference []Preference `xml:"preference"`
}
type Preferences struct {
	ServerPreferences ServerPreferences `xml:ServerPreferences"`
}

// A Policy defines how the scan behaved, what plugins were enabled etc.
type Policy struct {
	XMLName     xml.Name    `xml:"Policy"`
	Name        string      `xml:"policyName"`
	Preferences Preferences `xml:Preferences`
}

// A ReportItem represents a single finding made by nessus during the scan.
type ReportItem struct {
	XMLName xml.Name `xml:"ReportItem"`

	Port        int    `xml:"port,attr"`
	ServiceName string `xml:"svc_name,attr"`
	Protocol    string `xml:"protocol,attr"`
	Severity    string `xml:"severity,attr"`

	PluginID               string `xml:"pluginID,attr"`
	PluginName             string `xml:"pluginName,attr"`
	PluginFamily           string `xml:"pluginFamily,attr"`
	PluginModificationDate string `xml:"plugin_modification_date"`
	PluginPublicationDate  string `xml:"plugin_publication_date"`
	PluginType             string `xml:"plugin_type"`
	PluginOutput           string `xml:"plugin_output"`

	Description string `xml:"description"`
	RiskFactor  string `xml:"risk_factor"`
	Solution    string `xml:"solution"`
	Synopsis    string `xml:"synopsis"`

	SeeAlso string   `xml:"see_also"`
	CVE     []string `xml:"cve"`
	CWE     []string `xml:"cwe"`
	Xref    []string `xml:"xref"`
}

// A ReportHost bundles findings for a single host.
type ReportHost struct {
	XMLName     xml.Name     `xml:"ReportHost"`
	Name        string       `xml:"name,attr"`
	ReportItems []ReportItem `xml:"ReportItem"`
}

// A Report is a collection of findings grouped by hosts.
type Report struct {
	XMLName     xml.Name     `xml:"Report"`
	Name        string       `xml:"name,attr"`
	ReportHosts []ReportHost `xml:"ReportHost"`
}
type Result struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Policy  Policy   `xml:"Policy"`
	Report  Report   `xml:"Report"`
}

// ParseFile parses a nessus xml report (.nessus exports) file into a Result struct.
func ParseFile(path string) (*Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var v Result
	if err := xml.NewDecoder(file).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}

/*
func main() {
	result, err := ParseFile("xml/test_scan_gipz4m.nessus")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result)
}
*/
