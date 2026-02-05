package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog"
)

// exitWithDetails logs error details including HTTP response info if available.
func exitWithDetails(err error) {
	if rspErr, ok := err.(client.RspError); ok {
		klog.Infof("HTTP details: status=%d, body:\n%s", rspErr.StatusCode, rspErr.Body)
	}
	klog.Error(err.Error())
}

// connect creates and returns a CT log client for the specified URI.
func connect(_ context.Context, logURI string) *client.LogClient {
	var tlsCfg *tls.Config
	if skipHTTPSVerify {
		tlsCfg = &tls.Config{InsecureSkipVerify: skipHTTPSVerify}
	}

	httpClient := &http.Client{
		Timeout: 100 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          500,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsCfg,
		},
	}

	opts := jsonclient.Options{
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	}

	if pubKey != "" {
		pubkey, err := os.ReadFile(pubKey)
		if err != nil {
			klog.Exit(err)
		}
		opts.PublicKey = string(pubkey)
	}

	uri := logURI
	if logName != "" {
		llData, err := x509util.ReadFileOrURL(logList, httpClient)
		if err != nil {
			klog.Exitf("Failed to read log list: %v", err)
		}
		ll, err := loglist3.NewFromJSON(llData)
		if err != nil {
			klog.Exitf("Failed to build log list: %v", err)
		}

		logs := ll.FindLogByName(logName)
		if len(logs) == 0 {
			klog.Exitf("No log with name like %q found in loglist %q", logName, logList)
		}
		if len(logs) > 1 {
			logNames := make([]string, len(logs))
			for i, log := range logs {
				logNames[i] = fmt.Sprintf("%q", log.Description)
			}
			klog.Exitf("Multiple logs with name like %q found in loglist: %s", logName, strings.Join(logNames, ","))
		}
		uri = logs[0].URL
		if opts.PublicKey == "" {
			opts.PublicKeyDER = logs[0].Key
		}
	}

	klog.V(1).Infof("Use CT log at %s", uri)
	logClient, err := client.New(uri, httpClient, opts)
	if err != nil {
		klog.Exit(err)
	}

	return logClient
}
