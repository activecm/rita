package integration_rolling_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/activecm/rita/v5/cmd"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/util"

	"github.com/dchest/siphash"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

const logDir = "./historical/"
const futureLogDir = "./historical_future/"

type (
	Conn struct {
		TS          int64   `json:"ts"`
		UID         string  `json:"uid"`
		Src         string  `json:"id.orig_h"`
		SrcPort     int     `json:"id.orig_p"`
		Dst         string  `json:"id.resp_h"`
		DstPort     int     `json:"id.resp_p"`
		Proto       string  `json:"proto"`
		Service     string  `json:"service"`
		Duration    float64 `json:"duration"`
		OrigIPBytes int64   `json:"orig_ip_bytes"`
		RespIPBytes int64   `json:"resp_ip_bytes"`
	}

	HTTP struct {
		TS           int64    `json:"ts"`
		UID          string   `json:"uid"`
		Src          string   `json:"id.orig_h"`
		SrcPort      int      `json:"id.orig_p"`
		Dst          string   `json:"id.resp_h"`
		DstPort      int      `json:"id.resp_p"`
		Duration     float64  `json:"duration"`
		OrigIPBytes  int64    `json:"orig_ip_bytes"`
		RespIPBytes  int64    `json:"resp_ip_bytes"`
		TransDepth   int      `json:"trans_depth"`
		Method       string   `json:"method"`
		Host         string   `json:"host"`
		URI          string   `json:"uri"`
		Version      string   `json:"version"`
		Useragent    string   `json:"user_agent"`
		DstMimeTypes []string `json:"resp_mime_types"`
	}

	SSL struct {
		TS          int64   `json:"ts"`
		UID         string  `json:"uid"`
		Src         string  `json:"id.orig_h"`
		SrcPort     int     `json:"id.orig_p"`
		Dst         string  `json:"id.resp_h"`
		DstPort     int     `json:"id.resp_p"`
		Duration    float64 `json:"duration"`
		OrigIPBytes int64   `json:"orig_ip_bytes"`
		RespIPBytes int64   `json:"resp_ip_bytes"`
		ServerName  string  `json:"server_name"`
		JA3         string  `json:"ja3"`
	}

	DNS struct {
		TS        int64    `json:"ts"`
		UID       string   `json:"uid"`
		Src       string   `json:"id.orig_h"`
		SrcPort   int      `json:"id.orig_p"`
		Dst       string   `json:"id.resp_h"`
		DstPort   int      `json:"id.resp_p"`
		Query     string   `json:"query"`
		QTypeName string   `json:"qtype_name"`
		Answers   []string `json:"answers"`
	}
)

func (d *TTLTestSuite) TestHistoricalFirstSeen() {
	t := d.T()

	err := os.MkdirAll(logDir, os.ModePerm)
	require.NoError(t, err)

	err = os.MkdirAll(futureLogDir, os.ModePerm)
	require.NoError(t, err)

	startTS := time.Now().UTC().Add(-1 * time.Hour)
	regularIP, missingHost, ssl, http, dns, subdomain, domainIP := generateNormalLogs(t, startTS)
	openRegularIP, openMissingHost, openSSL, openHTTP := generateOpenLogs(t, startTS)
	startTS = time.Now().Add(60 * 24 * time.Hour).UTC()
	generateFutureLogs(t, startTS)

	// connect to clickhouse server
	server, err := database.ConnectToServer(context.Background(), d.cfg)
	require.NoError(t, err, "connecting to server should not produce an error")
	d.server = server

	err = server.Conn.Exec(server.GetContext(), "TRUNCATE TABLE IF EXISTS metadatabase.historical_first_seen")
	require.NoError(t, err)

	// import the mock data
	_, err = cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), logDir, "test_historical", true, true)
	require.NoError(t, err, "importing data should not produce an error")

	type res struct {
		IP        net.IP `ch:"ip"`
		FQDN      string `ch:"fqdn"`
		FirstSeen uint32 `ch:"first_seen"`
	}

	expectedFirstSeen := []res{
		{FQDN: "www.apple.com", FirstSeen: uint32(http)},
		{FQDN: "www.google.com", FirstSeen: uint32(ssl)},
		{FQDN: "www.maps.google.com", FirstSeen: uint32(openSSL)},
		{FQDN: "www.microsoft.com", FirstSeen: uint32(dns)},
		{FQDN: "www.time.apple.com", FirstSeen: uint32(openHTTP)},
		{FQDN: "www.update.microsoft.com", FirstSeen: uint32(subdomain)},
		{IP: net.ParseIP("23.76.54.8"), FirstSeen: uint32(openRegularIP)},
		{IP: net.ParseIP("52.25.67.8"), FirstSeen: uint32(openMissingHost)},
		{IP: net.ParseIP("53.89.44.30"), FirstSeen: uint32(domainIP)},
		{IP: net.ParseIP("66.85.26.1"), FirstSeen: uint32(openHTTP)},
		{IP: net.ParseIP("76.98.34.5"), FirstSeen: uint32(missingHost)},
		{IP: net.ParseIP("98.42.66.4"), FirstSeen: uint32(regularIP)},
	}

	var results []res
	err = server.Conn.Select(server.GetContext(), &results, `
		SELECT ip, fqdn, toUnixTimestamp(min(first_seen)) AS first_seen 
		FROM metadatabase.historical_first_seen
		GROUP BY ip, fqdn
		ORDER BY ip, fqdn
	`)
	require.NoError(t, err)
	require.Len(t, results, len(expectedFirstSeen))

	for i := range expectedFirstSeen {
		if expectedFirstSeen[i].IP != nil {
			require.Equal(t, expectedFirstSeen[i].IP, results[i].IP)
		} else {
			require.Equal(t, expectedFirstSeen[i].FQDN, results[i].FQDN)
		}

		require.Equal(t, expectedFirstSeen[i].FirstSeen, results[i].FirstSeen, "first seen timestamps should match for %s %s, expected: %s, got: %s", expectedFirstSeen[i].IP, expectedFirstSeen[i].FQDN, time.Unix(int64(expectedFirstSeen[i].FirstSeen), 0).UTC().String(), time.Unix(int64(results[i].FirstSeen), 0).UTC().String())
	}

	// import the future mock data
	_, err = cmd.RunImportCmd(time.Now(), d.cfg, afero.NewOsFs(), futureLogDir, "test_historical", true, true)
	require.NoError(t, err, "importing data should not produce an error")

	// make sure that all of the destinations are still there
	var totalCount uint64
	err = server.Conn.QueryRow(server.GetContext(), `
		SELECT count() FROM (
			SELECT DISTINCT ip, fqdn FROM metadatabase.historical_first_seen
		)
	`).Scan(&totalCount)
	require.NoError(t, err)
	require.EqualValues(t, len(expectedFirstSeen), totalCount, "there should still be %d entries in the historical table after importing future data", len(expectedFirstSeen))

	err = d.changeTime(91 * 24 * time.Hour)
	require.NoError(t, err)

	db, err := database.ConnectToDB(context.Background(), "metadatabase", d.cfg, nil)
	require.NoError(t, err)

	optimizeMetaDBTables(t, db, d.changeTime, 90*24*time.Hour, "historical_first_seen")

	type res2 struct {
		res
		LastSeen uint32 `ch:"last_seen"`
	}
	futureFirstSeen := []res{
		{FQDN: "www.apple.com", FirstSeen: uint32(http)},
		{FQDN: "www.microsoft.com", FirstSeen: uint32(dns)},
		{FQDN: "www.time.apple.com", FirstSeen: uint32(openHTTP)},
		{IP: net.ParseIP("23.76.54.8"), FirstSeen: uint32(openRegularIP)},
		{IP: net.ParseIP("53.89.44.30"), FirstSeen: uint32(domainIP)},
		{IP: net.ParseIP("66.85.26.1"), FirstSeen: uint32(openHTTP)},
		{IP: net.ParseIP("98.42.66.4"), FirstSeen: uint32(regularIP)},
	}

	var futureResults []res2
	err = server.Conn.Select(server.GetContext(), &futureResults, `
		SELECT ip, fqdn, toUnixTimestamp(min(first_seen)) AS first_seen, toUnixTimestamp(max(last_seen)) AS last_seen 
		FROM metadatabase.historical_first_seen
		GROUP BY ip, fqdn
		ORDER BY ip, fqdn
	`)
	require.NoError(t, err)
	require.Len(t, futureResults, len(futureFirstSeen))

	for i := range futureFirstSeen {
		if futureFirstSeen[i].IP != nil {
			require.Equal(t, futureFirstSeen[i].IP, futureResults[i].IP)
		} else {
			require.Equal(t, futureFirstSeen[i].FQDN, futureResults[i].FQDN)
		}
		// make sure last seen date is greater than or equal to 3 months from now
		require.GreaterOrEqual(t, futureResults[i].LastSeen, uint32(startTS.UTC().Unix()), "last seen timestamps should be gte to 3 months from now for %s %s, expected: %s, got: %s", futureFirstSeen[i].IP, futureFirstSeen[i].FQDN, startTS.UTC().String(), time.Unix(int64(futureResults[i].LastSeen), 0).UTC().String())
		// make sure that the first seen date is still the original first seen date
		// this is to ensure that the TTL didn't modify the date that
		require.Equal(t, futureFirstSeen[i].FirstSeen, futureResults[i].FirstSeen, "first seen timestamps should match for %s %s, expected: %s, got: %s", futureFirstSeen[i].IP, futureFirstSeen[i].FQDN, time.Unix(int64(futureFirstSeen[i].FirstSeen), 0).UTC().String(), time.Unix(int64(futureResults[i].FirstSeen), 0).UTC().String())
	}
}

func generateNormalLogs(t *testing.T, startTS time.Time) (int64, int64, int64, int64, int64, int64, int64) {
	t.Helper()

	// #1 10.55.100.100 -> 98.42.66.4
	// #2 10.55.200.10 -> 98.42.66.4 first (regular IP)

	// #3 10.55.100.100 -> 76.98.34.5 first (HTTP log missing host)
	// #4 10.55.200.10 -> 76.98.34.5

	// *** an IP -> IP connection ***
	ips1 := generateConn(t, startTS, "10.55.100.100", "98.42.66.4", 54374, 123)

	ips2 := generateConn(t, startTS, "10.55.200.10", "98.42.66.4", 45326, 123)
	// create timestamp a couple hours before other connections so that it is the first seen
	ips2[0].TS = time.Unix(ips2[0].TS, 0).Add(-2 * time.Hour).Unix()

	// *** an IP -> IP connection, where the dst was first seen as an HTTP connection w/ a missing host header ***
	ipsMissing3 := generateConn(t, startTS, "10.55.100.100", "76.98.34.5", 45326, 80)
	ipsMissing3[0].TS = time.Unix(ipsMissing3[0].TS, 0).Add(-2 * time.Hour).Unix()
	httpMissing3 := generateHTTP("10.55.100.100", "76.98.34.5", "", 45326, 80, ipsMissing3)

	ips4 := generateConn(t, startTS, "10.55.200.10", "76.98.34.5", 45326, 80)

	// #5 10.55.100.10 -> 53.89.44.30 -> www.google.com first (SSL)
	// #6 10.55.200.100 -> 53.89.44.30 -> www.google.com

	// #5 10.55.100.10 -> 53.89.44.30 -> www.apple.com
	// #6 10.55.200.100 -> 53.89.44.30 -> www.apple.com first (HTTP)

	// *** an IP -> FQDN connection over HTTP & SSL, first seen is SSL ***
	var ips5 []Conn
	ips5ForSSL := generateConn(t, startTS, "10.55.100.100", "53.89.44.30", 54374, 443)
	ips5ForSSL[0].TS = time.Unix(ips5ForSSL[0].TS, 0).Add(-2 * time.Hour).Unix()
	ips5ForHTTP := generateConn(t, startTS, "10.55.100.100", "53.89.44.30", 54374, 443)
	ips5 = append(ips5, ips5ForSSL...)
	ips5 = append(ips5, ips5ForHTTP...)
	ssl5 := generateSSL(t, "10.55.100.10", "53.89.44.30", "www.google.com", 98534, 443, ips5ForSSL)
	http5 := generateHTTP("10.55.100.10", "53.89.44.30", "www.google.com", 98534, 443, ips5ForHTTP)

	// *** an IP -> FQDN connection over HTTP & SSL, first seen is HTTP ***
	var ips6 []Conn
	ips6ForHTTP := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 45326, 80)
	ips6ForHTTP[0].TS = time.Unix(ips6ForHTTP[0].TS, 0).Add(-2 * time.Hour).Unix()
	ips6ForSSL := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 45326, 443)
	ssl6 := generateSSL(t, "10.55.200.10", "53.89.44.30", "www.apple.com", 98534, 443, ips6ForSSL)
	http6 := generateHTTP("10.55.200.10", "53.89.44.30", "www.apple.com", 98534, 80, ips6ForHTTP)
	ips6 = append(ips6, ips6ForSSL...)
	ips6 = append(ips6, ips6ForHTTP...)

	// #7 10.55.100.100 -> www.microsoft.com first (DNS)
	// #8 10.55.200.10 -> www.microsoft.com

	// #7 10.55.100.100 -> www.update.microsoft.com
	// #8 10.55.200.10 -> www.update.microsoft.com first (DNS)

	// *** an IP -> FQDN connection over HTTP, SSL, & DNS, first seen is DNS ***
	var ips7 []Conn
	ips7ForHTTP := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 54374, 80)
	ips7ForSSL := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 54374, 443)
	ips7ForDNS := generateConn(t, startTS, "10.55.100.100", "53.89.44.30", 54374, 53)
	ips7ForDNS[0].TS = time.Unix(ips7ForDNS[0].TS, 0).Add(-3 * time.Hour).Unix()
	ssl7 := generateSSL(t, "10.55.200.10", "53.89.44.30", "www.microsoft.com", 98534, 443, ips7ForSSL)
	http7 := generateHTTP("10.55.200.10", "53.89.44.30", "www.microsoft.com", 98534, 80, ips7ForHTTP)
	dns7 := generateDNS("10.55.100.100", "53.89.44.30", "www.microsoft.com", 54374, 53, ips7ForDNS)
	ips7 = append(ips7, ips7ForSSL...)
	ips7 = append(ips7, ips7ForHTTP...)

	// *** an IP -> FQDN connection over HTTP, SSL, & DNS, FQDN is not a TLD, first seen is DNS ***
	var ips8 []Conn
	ips8ForHTTP := generateConn(t, startTS, "10.55.100.100", "53.89.44.30", 54374, 80)
	ips8ForSSL := generateConn(t, startTS, "10.55.100.100", "53.89.44.30", 54374, 443)
	ips8ForDNS := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 54374, 53)
	ips8ForDNS[0].TS = time.Unix(ips8ForDNS[0].TS, 0).Add(-3 * time.Hour).Unix()
	ssl8 := generateSSL(t, "10.55.100.100", "53.89.44.30", "www.update.microsoft.com", 98534, 443, ips8ForSSL)
	http8 := generateHTTP("10.55.100.100", "53.89.44.30", "www.update.microsoft.com", 98534, 80, ips8ForHTTP)
	dns8 := generateDNS("10.55.200.10", "53.89.44.30", "www.update.microsoft.com", 54374, 53, ips8ForDNS)
	ips8 = append(ips8, ips8ForSSL...)
	ips8 = append(ips8, ips8ForHTTP...)

	f, err := os.OpenFile(logDir+"conn.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)

	var ips []Conn
	ips = append(ips, ips1...)
	ips = append(ips, ips2...)
	ips = append(ips, ipsMissing3...)
	ips = append(ips, ips4...)
	ips = append(ips, ips5...)
	ips = append(ips, ips6...)
	ips = append(ips, ips7...)
	ips = append(ips, ips8...)

	for _, d := range ips {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}

	f.Close()

	f, err = os.OpenFile(logDir+"http.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var https []HTTP
	https = append(https, httpMissing3...)
	https = append(https, http5...)
	https = append(https, http6...)
	https = append(https, http7...)
	https = append(https, http8...)

	for _, d := range https {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(logDir+"ssl.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var ssls []SSL
	ssls = append(ssls, ssl5...)
	ssls = append(ssls, ssl6...)
	ssls = append(ssls, ssl7...)
	ssls = append(ssls, ssl8...)

	for _, d := range ssls {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(logDir+"dns.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var dnss []DNS
	dnss = append(dnss, dns7...)
	dnss = append(dnss, dns8...)

	for _, d := range dnss {
		data, err := json.Marshal(&d) // #nosec G601s
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()
	// the DNS timestamps are not overwritten by the conn log timestamps since these logs are not linked via UID,
	// so they should not be included in this min calculation
	min1 := math.Min(
		float64(ips5ForSSL[0].TS),
		float64(ips6ForHTTP[0].TS),
	)

	firstForDomainIP := int64(min1)
	return ips2[0].TS, ipsMissing3[0].TS, ips5ForSSL[0].TS, ips6ForHTTP[0].TS, ips7ForDNS[0].TS, ips8ForDNS[0].TS, firstForDomainIP
}

func generateFutureLogs(t *testing.T, startTS time.Time) {
	t.Helper()
	ips1 := generateConn(t, startTS, "10.55.100.100", "98.42.66.4", 54374, 123)

	openips1 := generateConn(t, startTS, "10.55.100.100", "23.76.54.8", 54374, 123)

	// *** an IP -> FQDN connection over HTTP & SSL, first seen is SSL ***
	var ips6 []Conn
	ips6ForHTTP := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 45326, 80)
	ips6ForSSL := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 45326, 443)
	ssl6 := generateSSL(t, "10.55.200.10", "53.89.44.30", "www.apple.com", 98534, 443, ips6ForSSL)
	http6 := generateHTTP("10.55.200.10", "53.89.44.30", "www.apple.com", 98534, 80, ips6ForHTTP)
	ips6 = append(ips6, ips6ForSSL...)
	ips6 = append(ips6, ips6ForHTTP...)

	var openips6 []Conn
	openips6ForHTTP := generateConn(t, startTS, "10.55.200.10", "66.85.26.1", 45326, 80)
	openips6ForSSL := generateConn(t, startTS, "10.55.200.10", "66.85.26.1", 45326, 443)
	openssl6 := generateSSL(t, "10.55.200.10", "53.89.44.30", "www.time.apple.com", 98534, 443, openips6ForSSL)
	openhttp6 := generateHTTP("10.55.200.10", "53.89.44.30", "www.time.apple.com", 98534, 80, openips6ForHTTP)
	openips6 = append(openips6, openips6ForSSL...)
	openips6 = append(openips6, openips6ForHTTP...)

	// *** an IP -> FQDN connection over HTTP, SSL, & DNS, first seen is DNS ***
	var ips7 []Conn
	ips7ForHTTP := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 54374, 80)
	ips7ForSSL := generateConn(t, startTS, "10.55.200.10", "53.89.44.30", 54374, 443)
	ips7ForDNS := generateConn(t, startTS, "10.55.100.100", "53.89.44.30", 54374, 53)
	ips7ForDNS[0].TS = time.Unix(ips7ForDNS[0].TS, 0).Add(-3 * time.Hour).Unix()
	ssl7 := generateSSL(t, "10.55.200.10", "53.89.44.30", "www.microsoft.com", 98534, 443, ips7ForSSL)
	http7 := generateHTTP("10.55.200.10", "53.89.44.30", "www.microsoft.com", 98534, 80, ips7ForHTTP)
	dns7 := generateDNS("10.55.100.100", "53.89.44.30", "www.microsoft.com", 54374, 53, ips7ForDNS)
	ips7 = append(ips7, ips7ForSSL...)
	ips7 = append(ips7, ips7ForHTTP...)

	var ips []Conn
	ips = append(ips, ips1...)
	ips = append(ips, ips6...)
	ips = append(ips, ips7...)

	f, err := os.OpenFile(futureLogDir+"conn.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	for _, d := range ips {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}

	f.Close()

	f, err = os.OpenFile(futureLogDir+"open_conn.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var openips []Conn
	openips = append(openips, openips1...)
	openips = append(openips, openips6...)

	for _, d := range openips {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}

	f.Close()

	f, err = os.OpenFile(futureLogDir+"http.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var https []HTTP
	https = append(https, http6...)
	https = append(https, http7...)

	for _, d := range https {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(futureLogDir+"open_http.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	for _, d := range openhttp6 {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(futureLogDir+"ssl.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var ssls []SSL
	ssls = append(ssls, ssl6...)
	ssls = append(ssls, ssl7...)

	for _, d := range ssls {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(futureLogDir+"open_ssl.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)

	for _, d := range openssl6 {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(futureLogDir+"dns.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var dnss []DNS
	dnss = append(dnss, dns7...)

	for _, d := range dnss {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

}
func generateOpenLogs(t *testing.T, startTS time.Time) (int64, int64, int64, int64) {
	t.Helper()
	// #1 10.55.100.100 -> 23.76.54.8
	// #2 10.55.200.10 -> 23.76.54.8 first (regular openconn)

	// #3 10.55.100.100 -> 23.76.54.8 first (openhttp missing host)
	// #4 10.55.200.10 -> 23.76.54.8

	openips1 := generateConn(t, startTS, "10.55.100.100", "23.76.54.8", 54374, 123)
	// create timestamp a couple hours before other connections so that it is the first seen
	openips1[0].TS = time.Unix(openips1[0].TS, 0).Add(-2 * time.Hour).Unix()

	openips2 := generateConn(t, startTS, "10.55.200.10", "23.76.54.8", 45326, 23)

	openips3 := generateConn(t, startTS, "10.55.100.100", "52.25.67.8", 45326, 80)

	openipsMissing4 := generateConn(t, startTS, "10.55.200.10", "52.25.67.8", 45326, 80)
	openipsMissing4[0].TS = time.Unix(openipsMissing4[0].TS, 0).Add(-2 * time.Hour).Unix()
	openhttpMissing4 := generateHTTP("10.55.200.10", "52.25.67.8", "", 45326, 80, openipsMissing4)

	// 10.55.200.10 -> www.maps.google.com
	// 10.55.100.100 -> www.maps.google.com first (openssl)

	// 10.55.200.10 -> www.time.apple.com first (openhttp)
	// 10.55.100.100 -> www.time.apple.com

	// *** an IP -> FQDN connection over HTTP & SSL, first seen is SSL ***
	var openips5 []Conn
	openips5ForSSL := generateConn(t, startTS, "10.55.100.100", "66.85.26.1", 54374, 443)
	openips5ForSSL[0].TS = time.Unix(openips5ForSSL[0].TS, 0).Add(-2 * time.Hour).Unix()
	openips5ForHTTP := generateConn(t, startTS, "10.55.100.100", "66.85.26.1", 54374, 443)
	openips5 = append(openips5, openips5ForSSL...)
	openips5 = append(openips5, openips5ForHTTP...)
	openssl5 := generateSSL(t, "10.55.100.10", "66.85.26.1", "www.maps.google.com", 98534, 443, openips5ForSSL)
	openhttp5 := generateHTTP("10.55.100.10", "66.85.26.1", "www.maps.google.com", 98534, 443, openips5ForHTTP)

	// *** an IP -> FQDN connection over HTTP & SSL, first seen is SSL ***
	var openips6 []Conn
	openips6ForSSL := generateConn(t, startTS, "10.55.100.100", "66.85.26.1", 54374, 443)
	openips6ForHTTP := generateConn(t, startTS, "10.55.100.100", "66.85.26.1", 54374, 80)
	openips6ForHTTP[0].TS = time.Unix(openips6ForHTTP[0].TS, 0).Add(-3 * time.Hour).Unix()
	openips6 = append(openips6, openips6ForSSL...)
	openips6 = append(openips6, openips6ForHTTP...)
	openssl6 := generateSSL(t, "10.55.100.10", "66.85.26.1", "www.time.apple.com", 98534, 443, openips6ForSSL)
	openhttp6 := generateHTTP("10.55.100.10", "66.85.26.1", "www.time.apple.com", 98534, 443, openips6ForHTTP)

	f, err := os.OpenFile(logDir+"open_conn.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)

	var openips []Conn
	openips = append(openips, openips1...)
	openips = append(openips, openips2...)
	openips = append(openips, openips3...)
	openips = append(openips, openipsMissing4...)
	openips = append(openips, openips5...)
	openips = append(openips, openips6...)

	for _, d := range openips {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(logDir+"open_http.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var https []HTTP
	https = append(https, openhttpMissing4...)
	https = append(https, openhttp5...)
	https = append(https, openhttp6...)

	for _, d := range https {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()

	f, err = os.OpenFile(logDir+"open_ssl.log", os.O_CREATE|os.O_WRONLY, 0666)
	require.NoError(t, err)
	var ssls []SSL
	ssls = append(ssls, openssl5...)
	ssls = append(ssls, openssl6...)

	for _, d := range ssls {
		data, err := json.Marshal(&d) // #nosec G601
		require.NoError(t, err)
		_, err = fmt.Fprintf(f, "%s\n", data)
		require.NoError(t, err)
	}
	f.Close()
	return openips1[0].TS, openipsMissing4[0].TS, openips5ForSSL[0].TS, openips6ForHTTP[0].TS

}

func generateHTTP(src string, dst string, fqdn string, srcPort, dstPort int, conns []Conn) []HTTP {
	var ips []HTTP
	for _, conn := range conns {
		ips = append(ips, HTTP{
			TS:           conn.TS,
			UID:          conn.UID,
			Src:          src,
			Dst:          dst,
			SrcPort:      srcPort,
			DstPort:      dstPort,
			TransDepth:   1,
			Method:       "GET",
			Host:         fqdn,
			URI:          "/hello_world.png",
			Version:      "1.1",
			Useragent:    "Bing Bong Kirbo",
			Duration:     conn.Duration,
			OrigIPBytes:  conn.OrigIPBytes,
			RespIPBytes:  conn.RespIPBytes,
			DstMimeTypes: []string{"image/png"},
		})
	}
	return ips
}

func generateDNS(src string, dst string, fqdn string, srcPort, dstPort int, conns []Conn) []DNS {
	var ips []DNS
	for _, conn := range conns {
		ips = append(ips, DNS{
			TS:        conn.TS,
			UID:       conn.UID,
			Src:       src,
			Dst:       dst,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Query:     fqdn,
			QTypeName: "A",
			Answers:   []string{"63.46.7.32"},
		})
	}
	return ips
}

func generateSSL(t *testing.T, src string, dst string, fqdn string, srcPort, dstPort int, conns []Conn) []SSL {
	var ips []SSL
	for _, conn := range conns {
		ja3, err := util.NewFixedStringHash(src, dst, fmt.Sprint(srcPort), fmt.Sprint(dstPort), fqdn)
		require.NoError(t, err)

		ips = append(ips, SSL{
			TS:          conn.TS,
			UID:         conn.UID,
			Src:         src,
			Dst:         dst,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			ServerName:  fqdn,
			Duration:    conn.Duration,
			OrigIPBytes: conn.OrigIPBytes,
			RespIPBytes: conn.RespIPBytes,
			JA3:         ja3.Hex(),
		})
	}
	return ips
}

func generateConn(t *testing.T, startTS time.Time, src string, dst string, srcPort, dstPort int) []Conn {
	t.Helper()
	var ips []Conn
	for i := 0; i < 15; i++ {
		proto := "tcp"
		service := "ntp"
		ts := startTS.Add(time.Duration(randRange(1, 5)) * time.Minute).Add(time.Duration(randRange(1, 40)) * time.Second)
		srcIP := net.ParseIP(src)
		require.NotNil(t, srcIP)
		dstIP := net.ParseIP(dst)
		require.NotNil(t, dstIP)

		var key []byte
		s := make([]byte, 4)
		binary.LittleEndian.PutUint32(s, uint32(srcPort))
		key = append(key, s...)
		binary.LittleEndian.PutUint32(s, uint32(dstPort))
		key = append(key, s...)

		key = append(key, []byte(proto)...)
		key = append(key, []byte(service)...)

		ii := make([]byte, 2)
		binary.LittleEndian.PutUint16(s, uint16(i))
		key = append(key, ii...)
		// key = append(key, dstIP...)

		tb := make([]byte, 8)
		binary.LittleEndian.PutUint64(tb, uint64(ts.Unix()))
		// key = append(key, tb...)
		h := siphash.New128(key)
		h.Write(srcIP)
		h.Write(dstIP)
		h.Write(tb)
		hSum := h.Sum(nil)

		hash := make([]byte, 12)
		copy(hash, hSum[:8])       // copy first 8 bytes
		copy(hash[8:], hSum[8:12]) // Copy 4 bytes from the second uint64

		hashStr := base64.StdEncoding.EncodeToString(hash)

		ips = append(ips, Conn{
			TS:          ts.Unix(),
			UID:         hashStr,
			Src:         src,
			Dst:         dst,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			Proto:       proto,
			Service:     service,
			Duration:    (time.Duration(randRange(1, 40)) * time.Second).Seconds(),
			OrigIPBytes: int64(randRange(10, 10000)),
			RespIPBytes: int64(randRange(10, 10000)),
		})
	}
	return ips
}

func randRange(min, max int) int {
	return rand.Intn(max-min) + min // #nosec G404: not used for security purposes
}
