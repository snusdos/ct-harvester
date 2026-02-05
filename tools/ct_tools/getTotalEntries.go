package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/number"
)

// CTLLog is the JSON data from the CTL log list
type CTLLog struct {
	Operators []struct {
		Logs []struct {
			URL string `json:"url"`
		} `json:"logs"`
	} `json:"operators"`
}

// LogInfo is the response structure from each log's get-sth endpoint
type LogInfo struct {
	TreeSize int64 `json:"tree_size"`
}

func main() {

	p := message.NewPrinter(language.English)

	resp, err := http.Get("https://www.gstatic.com/ct/log_list/v3/all_logs_list.json") // https://www.gstatic.com/ct/log_list/v3/log_list.json
	if err != nil {
		log.Fatalf("Failed to get CTL log list: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	var ctlLog CTLLog
	if err := json.Unmarshal(body, &ctlLog); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	totalCerts := int64(0)

	for _, operator := range ctlLog.Operators {
		for _, logEntry := range operator.Logs {
			logURL := fmt.Sprintf("%sct/v1/get-sth", logEntry.URL)
			logResp, err := http.Get(logURL)
			if err != nil {
				log.Printf("Failed to get information for %s: %v", logEntry.URL, err)
				continue
			}
			defer logResp.Body.Close()

			logBody, err := io.ReadAll(logResp.Body)
			if err != nil {
				log.Printf("Failed to read log body for %s: %v", logEntry.URL, err)
				continue
			}

			var logInfo LogInfo
			if err := json.Unmarshal(logBody, &logInfo); err != nil {
				log.Printf("Failed to unmarshal log info for %s: %v", logEntry.URL, err)
				continue
			}

			totalCerts += logInfo.TreeSize

			p.Printf("%s has %v certificates\n", logEntry.URL, number.Decimal(logInfo.TreeSize))
		}
	}

	p.Printf("Total certs -> %v\n", number.Decimal(totalCerts))
}
