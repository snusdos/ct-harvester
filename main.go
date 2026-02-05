package main

import (
	"bufio"
	"context"
	"encoding/pem"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/uuid"
	"github.com/schollz/progressbar/v3"
	"k8s.io/klog"
)

var (
	skipHTTPSVerify bool
	logName         string
	logList         string
	pubKey          string
	chainOut        bool
	textOut         bool
	preOut          bool
	outputFile      *os.File
	lock            sync.Mutex
)

func main() {
	ctx := context.Background()
	var wg sync.WaitGroup

	// Create error output file
	var err error
	outputFile, err = os.Create("data/output.txt")
	if err != nil {
		klog.Exitf("Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Read log URIs from file
	file, err := os.Open("data/xenonsubset.txt")
	if err != nil {
		klog.Exitf("Failed to read log URI file: %v", err)
	}
	defer file.Close()

	// Configuration
	skipHTTPSVerify = true
	chainOut = false // Output entire chain or only leaf certificate
	textOut = false  // Output as .pem or .txt
	preOut = false   // Include precertificates

	// Separate goroutine is spawned for each log to fetch entries in parallel. Each line in file is a CT log URL.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		logURI := scanner.Text()
		fmt.Printf("Running Log: %s\n", logURI)
		wg.Add(1)
		go func(uri string) {
			defer wg.Done()
			runGetEntries(ctx, uri)
		}(logURI)
	}

	if err := scanner.Err(); err != nil {
		klog.Errorf("Error reading URIs: %v", err)
	}

	wg.Wait()
}

// runGetEntries fetches certificate entries from a CT log using random sampling.
func runGetEntries(ctx context.Context, logURI string) {
	var logReturnedEntries int64

	logClient := connect(ctx, logURI)

	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		fmt.Println("STH ERROR FROM:", logURI)
		return
	}

	treeSize := sth.TreeSize

	// Query 1% of the log, with 5000000 as lower bound
	entriesPerLog := math.Floor(0.01 * float64(treeSize))
	if entriesPerLog < 5000000 {
		entriesPerLog = 5000000
	}
	if entriesPerLog > float64(treeSize) {
		entriesPerLog = float64(treeSize)
	}

	bar := progressbar.NewOptions64(
		int64(entriesPerLog),
		progressbar.OptionSetDescription(logURI),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionShowIts(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionFullWidth(),
		progressbar.OptionClearOnFinish(),
	)

	for logReturnedEntries < int64(entriesPerLog) {
		getFirst := calcRand(int64(treeSize)) // random index within the tree
		getLast := getFirst + 999             // fetch 1000 (or however many is returned by log) entries in a batch

		rsp, err := logClient.GetRawEntries(ctx, getFirst, getLast)
		if err != nil {
			fmt.Fprintf(outputFile, "GetRawEntries Error: %s From: %s\n", err, logURI)
			exitWithDetails(err)
			return
		}

		entriesReturned := int64(len(rsp.Entries))
		if entriesReturned == 0 {
			fmt.Fprintf(outputFile, "No entries returned for logURI: %s\n", logURI)
			break
		}

		for i, rawEntry := range rsp.Entries {
			rleIndex := getFirst + int64(i)
			rle, err := ct.RawLogEntryFromLeaf(rleIndex, &rawEntry)
			if err != nil {
				fmt.Fprintf(outputFile, "Index=%d Failed to unmarshal leaf entry: %v\n", rleIndex, err)
				continue
			}
			showRawLogEntry(rle)
		}

		logReturnedEntries += entriesReturned
		bar.Set64(logReturnedEntries)
	}

	fmt.Fprintf(outputFile, "logURI: %s Finished at: %s Total Entries: %v\n", logURI, time.Now(), logReturnedEntries)
	bar.Finish()
}

// showRawLogEntry processes a raw log entry and outputs the certificate.
func showRawLogEntry(rle *ct.RawLogEntry) {
	ts := rle.Leaf.TimestampedEntry
	when := ct.TimestampToTime(ts.Timestamp)
	tsFilename := when.Format("20060102150405")

	switch ts.EntryType {
	case ct.X509LogEntryType:
		showRawCert(*ts.X509Entry, tsFilename)
	case ct.PrecertLogEntryType:
		if preOut {
			showRawCert(rle.Cert, tsFilename)
		}
	default:
		fmt.Fprintf(outputFile, "Unhandled log entry type %d\n", ts.EntryType)
	}

	if chainOut {
		for _, c := range rle.Chain {
			showRawCert(c, tsFilename)
		}
	}
}

// showRawCert outputs a certificate as PEM or parsed text based on configuration.
func showRawCert(cert ct.ASN1Cert, timestamp string) {
	if textOut {
		c, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			klog.Errorf("Error parsing certificate: %q", err.Error())
			return
		}
		if c == nil {
			return
		}
		showParsedCert(c, timestamp)
	} else {
		showPEMData(cert.Data, timestamp)
	}
}

// showParsedCert outputs a parsed certificate to a text file.
func showParsedCert(cert *x509.Certificate, timestamp string) {
	serialNumber := fmt.Sprintf("%x", cert.SerialNumber)
	fileName := fmt.Sprintf("xxx\\%s-%x.pem", timestamp, serialNumber)

	sOutputFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s\n", err)
		return
	}
	defer sOutputFile.Close()

	if textOut {
		certDetails := x509util.CertificateToString(cert)
		if _, err := fmt.Fprintf(sOutputFile, "%s\n", certDetails); err != nil {
			fmt.Printf("Failed to write to file: %v\n", err)
		}
		return
	}
	showPEMData(cert.Raw, timestamp)
}

// showPEMData writes certificate data as a PEM file.
func showPEMData(data []byte, timestamp string) {
	id := uuid.New()
	fileName := fmt.Sprintf("xxx\\%s_%s.pem", timestamp, id)

	sOutputFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("Failed to create file: %s\n", err)
		return
	}
	defer sOutputFile.Close()

	lock.Lock()
	defer lock.Unlock()

	if err := pem.Encode(sOutputFile, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		klog.Errorf("Failed to PEM encode cert: %q", err.Error())
	}
}

// calcRand returns a random index within the tree, ensuring enough room for batch fetches.
func calcRand(n int64) int64 {
	rnum := rand.Int63n(n)
	if rnum >= n-1000 {
		return rnum - 1000
	}
	return rnum
}
