package importer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/activecm/rita/v5/config"
	c "github.com/activecm/rita/v5/constants"
	"github.com/activecm/rita/v5/database"
	"github.com/activecm/rita/v5/importer/zeektypes"
	zlog "github.com/activecm/rita/v5/logger"
	"github.com/activecm/rita/v5/progressbar"
	"github.com/activecm/rita/v5/util"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/spf13/afero"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/sync/errgroup"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/time/rate"
)

var ErrAllFilesPreviouslyImported = errors.New("all files were previously imported")

type zeekRecord interface {
	zeektypes.Conn | zeektypes.DNS | zeektypes.HTTP | zeektypes.SSL
}

type Importer struct {
	Cfg                      *config.Config
	Database                 *database.DB
	ImportID                 util.FixedString
	LogDirectory             string
	FileMap                  map[string][]string
	EntryChannels            EntryChans
	MetaDBChannel            chan MetaDBFile
	Paths                    chan string
	ErrChannel               chan error
	TotalFileCount           int
	DoneChannels             DoneChans
	Writers                  writers
	WriteLimiter             *rate.Limiter
	ProgressBar              *mpb.Progress
	FileProgressBar          *mpb.Bar
	ProgressLogger           *log.Logger
	HTTPLinkMutex            sync.Mutex
	OpenHTTPLinkMutex        sync.Mutex
	NumParsers               int
	NumDigesters             int
	NumWriters               int
	ResultCounts             ResultCounts
	wg                       WaitGroups
	importStartedCallback    func(util.FixedString) error
	validateLogFilesCallback func(map[string][]string) (int, error)
	startWritersCallback     func(int)
	closeWritersCallback     func()
	markFileImportedCallback func(util.FixedString, util.FixedString, string) error
}

type EntryChans struct {
	Conn     chan zeektypes.Conn
	OpenConn chan zeektypes.Conn
	DNS      chan zeektypes.DNS
	HTTP     chan zeektypes.HTTP
	OpenHTTP chan zeektypes.HTTP
	SSL      chan zeektypes.SSL
	OpenSSL  chan zeektypes.SSL
}

type writers struct {
	ConnTmp     *database.BulkWriter
	OpenConnTmp *database.BulkWriter
	DNS         *database.BulkWriter
	PDNS        *database.BulkWriter
	HTTPTmp     *database.BulkWriter
	OpenHTTPTmp *database.BulkWriter
	SSLTmp      *database.BulkWriter
	OpenSSLTmp  *database.BulkWriter
}

type DoneChans struct {
	filesDone chan struct{}
	conn      chan struct{}
	openconn  chan struct{}
	http      chan struct{}
	openhttp  chan struct{}
	dns       chan struct{}
	ssl       chan struct{}
	openssl   chan struct{}
}

type ResultCounts struct {
	ZeekUIDs       uint64
	OpenZeekUIDs   uint64
	UnfilteredConn uint64
	Conn           uint64
	OpenConn       uint64
	HTTP           uint64
	OpenHTTP       uint64
	DNS            uint64
	UDNS           int64
	PDNSRaw        uint64
	SSL            uint64
	OpenSSL        uint64
}

type WaitGroups struct {
	Digester sync.WaitGroup
	MetaDB   sync.WaitGroup
	OpenConn sync.WaitGroup
	Conn     sync.WaitGroup
	DNS      sync.WaitGroup
	HTTP     sync.WaitGroup
	OpenHTTP sync.WaitGroup
	SSL      sync.WaitGroup
	OpenSSL  sync.WaitGroup
}

// NewImporter creates and returns a new Importer object
func NewImporter(db *database.DB, cfg *config.Config, importStartedAt time.Time, numDigesters int, numParsers int, numWriters int) (*Importer, error) {
	logger := zlog.GetLogger()

	// create channels to hold the network traffic entries
	entryChannels := EntryChans{
		Conn:     make(chan zeektypes.Conn, 1000),
		OpenConn: make(chan zeektypes.Conn, 1000),
		DNS:      make(chan zeektypes.DNS, 1000),
		HTTP:     make(chan zeektypes.HTTP, 1000),
		OpenHTTP: make(chan zeektypes.HTTP, 1000),
		SSL:      make(chan zeektypes.SSL, 1000),
		OpenSSL:  make(chan zeektypes.SSL, 1000),
	}

	// create channels to keep track of log files being successfully imported
	doneChannels := DoneChans{
		filesDone: make(chan struct{}),
		conn:      make(chan struct{}, numDigesters),
		openconn:  make(chan struct{}, numDigesters),
		http:      make(chan struct{}, numDigesters),
		openhttp:  make(chan struct{}, numDigesters),
		dns:       make(chan struct{}, numDigesters),
		ssl:       make(chan struct{}, numDigesters),
		openssl:   make(chan struct{}, numDigesters),
	}

	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)

	// create writer objects to write output data to the individual log collections
	logWriters := writers{
		ConnTmp:     database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "conn_tmp", "INSERT INTO {database:Identifier}.conn_tmp", limiter, false),
		OpenConnTmp: database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "openconn_tmp", "INSERT INTO {database:Identifier}.openconn_tmp", limiter, false),
		DNS:         database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "dns", "INSERT INTO {database:Identifier}.dns", limiter, false),
		PDNS:        database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "pdns", "INSERT INTO {database:Identifier}.pdns_raw", limiter, false),
		HTTPTmp:     database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "http_tmp", "INSERT INTO {database:Identifier}.http_tmp", limiter, false),
		OpenHTTPTmp: database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "openhttp_tmp", "INSERT INTO {database:Identifier}.openhttp_tmp", limiter, false),
		SSLTmp:      database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "ssl_tmp", "INSERT INTO {database:Identifier}.ssl_tmp", limiter, false),
		OpenSSLTmp:  database.NewBulkWriter(db, cfg, numWriters, db.GetSelectedDB(), "openssl_tmp", "INSERT INTO {database:Identifier}.openssl_tmp", limiter, false),
	}

	// create progressBar bar
	progressBar := mpb.New(mpb.WithWidth(64))

	// set the overall db import start time
	db.ImportStartedAt = importStartedAt

	// create a unique import id using the start time
	importID, err := util.NewFixedStringHash(strconv.FormatInt(importStartedAt.UnixMicro(), 10))
	if err != nil {
		return nil, err
	}

	// log the import id
	logger.Debug().Str("import_id", importID.Hex()).Send()

	// return the importer object
	return &Importer{
		Database: db,
		Cfg:      cfg,
		ImportID: importID,
		// LogDirectory:             directory,
		FileMap:                  make(map[string][]string),
		EntryChannels:            entryChannels,
		MetaDBChannel:            make(chan MetaDBFile),
		Paths:                    make(chan string, 10),
		ErrChannel:               make(chan error, 100),
		DoneChannels:             doneChannels,
		Writers:                  logWriters,
		WriteLimiter:             rate.NewLimiter(5, 5),
		ProgressBar:              progressBar,
		ProgressLogger:           log.New(progressBar, "", 0),
		NumParsers:               numParsers,
		NumDigesters:             numDigesters,
		NumWriters:               numWriters,
		ResultCounts:             ResultCounts{},
		importStartedCallback:    db.AddImportStartRecordToMetaDB,
		validateLogFilesCallback: db.CheckIfFilesWereAlreadyImported,
		startWritersCallback:     logWriters.startWriters,
		closeWritersCallback:     logWriters.closeWriters,
		markFileImportedCallback: db.MarkFileImportedInMetaDB,
	}, nil
}

func (importer *Importer) Import(afs afero.Fs, files map[string][]string) error {
	logger := zlog.GetLogger()

	// record the hourlyImportStart time of this import chunk
	hourlyImportStart := time.Now()

	// check if files have already been imported make a map of the remaining files
	totalFileCount, err := importer.validateLogFilesCallback(files)
	if err != nil {
		return err
	}

	// verify that there are still files left to import and set file count
	if totalFileCount < 1 {
		return ErrAllFilesPreviouslyImported
	}
	importer.TotalFileCount = totalFileCount

	// set up the file map with the remaining files
	importer.FileMap = files

	// add import started record to metadatabase
	err = importer.importStartedCallback(importer.ImportID)
	if err != nil {
		return err
	}

	// initialize progress bar
	importer.FileProgressBar = importer.ProgressBar.New(int64(importer.TotalFileCount),
		mpb.BarStyle().Lbound("╢").Filler("▌").Tip("▌").Padding("░").Rbound("╟"),
		mpb.PrependDecorators(
			// display our name with one space on the right
			decor.Name("Log Parsing", decor.WC{C: decor.DindentRight | decor.DextraSpace}),
			// replace ETA decorator with "done" message, OnComplete event
			decor.OnComplete(decor.Elapsed(decor.ET_STYLE_GO), "🎉"),
		),
		mpb.AppendDecorators(decor.CountersNoUnit("%d / %d")),
	)

	// start the import
	importer.process(afs)

	// record import time to logger
	hourlyImportEnd := time.Now()
	logger.Info().Time("parsing_began", hourlyImportStart).Time("parsing_finished", hourlyImportEnd).Str("elapsed_time", time.Since(hourlyImportStart).String()).Msg("Finished Parsing Logs! 🎉")

	if err := importer.season(); err != nil {
		return err
	}
	seasoningEnd := time.Now()
	logger.Info().Time("seasoning_began", hourlyImportEnd).Time("seasoning_finished", seasoningEnd).Str("elapsed_time", time.Since(hourlyImportEnd).String()).Msg("Finished Seasoning Logs! 🎉")

	// create formatter for adding commas in the counts
	p := message.NewPrinter(language.English)
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.Conn)).Msg("Imported conn records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.OpenConn)).Msg("Imported open conn records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.DNS)).Msg("Imported dns records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.PDNSRaw)).Msg("Imported pdns raw records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.HTTP)).Msg("Imported http records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.OpenHTTP)).Msg("Imported open http records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.SSL)).Msg("Imported ssl records")
	logger.Debug().Str("count", p.Sprintf("%d", importer.ResultCounts.OpenSSL)).Msg("Imported open ssl records")

	return nil
}

// process loads the files and parses the raw log entries
func (importer *Importer) process(afs afero.Fs) {
	// initialize writers
	importer.startWritersCallback(importer.NumWriters)

	// start goroutines to write network traffic entries to the database
	importer.startParseRoutines()

	// start goroutines to parse log file contents
	importer.startDigesters(afs)

	// start goroutine to mark files as imported in MetaDB
	importer.startMetaDBFileTracker()

	// start listener routine and feed initial files in to paths channel
	importer.feedAndListenForFileCompletion()

	// close log entry and map channels
	go func() {
		// wait for our bar to complete and flush
		importer.ProgressBar.Wait()

		// close log entry channels
		close(importer.EntryChannels.Conn)
		close(importer.EntryChannels.OpenConn)
		close(importer.EntryChannels.DNS)
		close(importer.EntryChannels.HTTP)
		close(importer.EntryChannels.OpenHTTP)
		close(importer.EntryChannels.SSL)
		close(importer.EntryChannels.OpenSSL)

		// close paths channel
		close(importer.Paths)
		// close metadb channel
		close(importer.MetaDBChannel)
	}()

	// wait for log routine groups
	importer.wg.Conn.Wait()
	importer.wg.OpenConn.Wait()
	importer.wg.DNS.Wait()
	importer.wg.HTTP.Wait()
	importer.wg.OpenHTTP.Wait()
	importer.wg.SSL.Wait()
	importer.wg.OpenSSL.Wait()

	close(importer.DoneChannels.conn)
	close(importer.DoneChannels.openconn)
	close(importer.DoneChannels.http)
	close(importer.DoneChannels.openhttp)
	close(importer.DoneChannels.ssl)
	close(importer.DoneChannels.openssl)
	close(importer.DoneChannels.dns)
	close(importer.DoneChannels.filesDone)

	close(importer.ErrChannel)

	// close writers
	importer.closeWritersCallback()
}

// startParseRoutines starts a fixed number of goroutines to parse lines from logs into data to be written to the db.
func (importer *Importer) startParseRoutines() {
	importer.wg.Conn.Add(importer.NumParsers)
	importer.wg.OpenConn.Add(importer.NumParsers)
	importer.wg.DNS.Add(importer.NumParsers)
	importer.wg.HTTP.Add(importer.NumParsers)
	importer.wg.OpenHTTP.Add(importer.NumParsers)
	importer.wg.SSL.Add(importer.NumParsers)
	importer.wg.OpenSSL.Add(importer.NumParsers)

	for i := 0; i < importer.NumParsers; i++ {
		go func(_ int) {
			// parseConn(importer.EntryChannels.Conn, importer.Writers.Conn.WriteChannel, importer.UniqueMaps.Uconn, importer.UniqueMaps.ZeekUIDs, importer.ImportID, &importer.ResultCounts.Conn)
			parseConn(importer.Cfg, importer.EntryChannels.Conn, importer.Writers.ConnTmp.WriteChannel, importer.ImportID, importer.Database.ImportStartedAt, &importer.ResultCounts.Conn)
			importer.wg.Conn.Done()
		}(i)
		go func(_ int) {
			// parseConn(importer.EntryChannels.OpenConn, importer.Writers.OpenConn.WriteChannel, importer.UniqueMaps.OpenConn, importer.UniqueMaps.OpenZeekUIDs, importer.ImportID, &importer.ResultCounts.OpenConn)
			parseConn(importer.Cfg, importer.EntryChannels.OpenConn, importer.Writers.OpenConnTmp.WriteChannel, importer.ImportID, importer.Database.ImportStartedAt, &importer.ResultCounts.OpenConn)
			importer.wg.OpenConn.Done()
		}(i)

		go func(_ int) {
			parseDNS(importer.Cfg, importer.EntryChannels.DNS, importer.Writers.DNS.WriteChannel, importer.Writers.PDNS.WriteChannel, &importer.ResultCounts.DNS, &importer.ResultCounts.PDNSRaw, importer.Database.ImportStartedAt)
			importer.wg.DNS.Done()
		}(i)

		go func(_ int) {
			parseHTTP(importer.Cfg, importer.EntryChannels.HTTP, importer.Writers.HTTPTmp.WriteChannel, importer.Database.ImportStartedAt, &importer.ResultCounts.HTTP, &importer.ResultCounts.Conn)
			importer.wg.HTTP.Done()
		}(i)

		go func(_ int) {
			parseHTTP(importer.Cfg, importer.EntryChannels.OpenHTTP, importer.Writers.OpenHTTPTmp.WriteChannel, importer.Database.ImportStartedAt, &importer.ResultCounts.OpenHTTP, &importer.ResultCounts.OpenConn)
			importer.wg.OpenHTTP.Done()
		}(i)

		go func(_ int) {
			parseSSL(importer.Cfg, importer.EntryChannels.SSL, importer.Writers.SSLTmp.WriteChannel, importer.Database.ImportStartedAt, &importer.ResultCounts.SSL)
			importer.wg.SSL.Done()
		}(i)

		go func(_ int) {
			parseSSL(importer.Cfg, importer.EntryChannels.OpenSSL, importer.Writers.OpenSSLTmp.WriteChannel, importer.Database.ImportStartedAt, &importer.ResultCounts.OpenSSL)
			importer.wg.OpenSSL.Done()
		}(i)
	}
}

// startDigesters starts a fixed number of goroutines to read and digest files.
func (importer *Importer) startDigesters(afs afero.Fs) {
	importer.wg.Digester.Add(importer.NumDigesters)
	for i := 0; i < importer.NumDigesters; i++ {
		go func(_ int) {
			digester(afs, importer.DoneChannels, importer.Paths, importer.ErrChannel, importer.EntryChannels, importer.MetaDBChannel, importer.Database.GetSelectedDB(), importer.ImportID, importer.ProgressLogger)
			importer.wg.Digester.Done()
		}(i)
	}
}

// startMetaDBFileTracker starts a goroutine to mark files as imported in MetaDB
func (importer *Importer) startMetaDBFileTracker() {

	importer.wg.MetaDB.Add(1)
	go func() {
		for metaDB := range importer.MetaDBChannel {
			err := importer.markFileImportedCallback(metaDB.fileHash, metaDB.importID, metaDB.path)
			if err != nil {
				importer.ProgressLogger.Println("[WARNING] could not mark file as imported, path:", metaDB.path, err)
			}
		}
		importer.wg.MetaDB.Done()
	}()

}

// feedAndListenForFileCompletion feeds files to the paths channel and listens for the completion of each log type
// to orchestrate feeding other log types into the paths channel
func (importer *Importer) feedAndListenForFileCompletion() {
	// listen for file completion of each log type
	go func() {
		for importer.FileProgressBar.Current() < int64(importer.TotalFileCount) {

			select {
			// read from other log types' done channels so that they don't block
			case <-importer.DoneChannels.conn:
			case <-importer.DoneChannels.openconn:
			case <-importer.DoneChannels.http:
			case <-importer.DoneChannels.openhttp:
			case <-importer.DoneChannels.ssl:
			case <-importer.DoneChannels.openssl:
			case <-importer.DoneChannels.dns:

			// increment progress bar
			case <-importer.DoneChannels.filesDone:
				importer.FileProgressBar.Increment()
			default:
			}

		}
	}()

	if len(importer.FileMap[c.ConnPrefix]) > 0 {
		for _, connLog := range importer.FileMap[c.ConnPrefix] {
			importer.Paths <- connLog
		}
		for _, httpLog := range importer.FileMap[c.HTTPPrefix] {
			importer.Paths <- httpLog
		}
		for _, sslLog := range importer.FileMap[c.SSLPrefix] {
			importer.Paths <- sslLog
		}
	}
	if len(importer.FileMap[c.OpenConnPrefix]) > 0 {
		for _, openConnLog := range importer.FileMap[c.OpenConnPrefix] {
			importer.Paths <- openConnLog
		}
		for _, openHTTPLog := range importer.FileMap[c.OpenHTTPPrefix] {
			importer.Paths <- openHTTPLog
		}
		for _, openSSLLog := range importer.FileMap[c.OpenSSLPrefix] {
			importer.Paths <- openSSLLog
		}
	}
	for _, dnsLog := range importer.FileMap[c.DNSPrefix] {
		importer.Paths <- dnsLog
	}
}

// digester loops over the paths, checks the file prefix, and sends each path to the parser with its corresponding entryChannel until either paths or done is closed.
func digester(afs afero.Fs, done DoneChans, paths <-chan string, errc chan error, entryChannels EntryChans, metaDBChan chan<- MetaDBFile, dbName string, importID util.FixedString, progressLogger *log.Logger) {
	// errc := make(chan error)

	// read entries from err channel, handle specific errors if necessary
	// currently, this err channel is primarily used for checking errors in tests
	go func() {
		for err := range errc {
			_ = err
		}
	}()

	// loop over paths and send to parseFiles with the correct corresponding entryChannels, sending a done signal for each completed file
	for path := range paths {
		progressLogger.Println("[-] Parsing: ", path)
		switch {
		case strings.HasPrefix(filepath.Base(path), c.ConnPrefix):
			parseFile(afs, path, entryChannels.Conn, errc, metaDBChan, dbName, importID)
			done.conn <- struct{}{}
		case strings.HasPrefix(filepath.Base(path), c.OpenConnPrefix):
			parseFile(afs, path, entryChannels.OpenConn, errc, metaDBChan, dbName, importID)
			done.openconn <- struct{}{}
		case strings.HasPrefix(filepath.Base(path), c.DNSPrefix):
			parseFile(afs, path, entryChannels.DNS, errc, metaDBChan, dbName, importID)
			done.dns <- struct{}{}
		case strings.HasPrefix(filepath.Base(path), c.HTTPPrefix):
			parseFile(afs, path, entryChannels.HTTP, errc, metaDBChan, dbName, importID)
			done.http <- struct{}{}
		case strings.HasPrefix(filepath.Base(path), c.OpenHTTPPrefix):
			parseFile(afs, path, entryChannels.OpenHTTP, errc, metaDBChan, dbName, importID)
			done.openhttp <- struct{}{}
		case strings.HasPrefix(filepath.Base(path), c.SSLPrefix):
			parseFile(afs, path, entryChannels.SSL, errc, metaDBChan, dbName, importID)
			done.ssl <- struct{}{}
		case strings.HasPrefix(filepath.Base(path), c.OpenSSLPrefix):
			parseFile(afs, path, entryChannels.OpenSSL, errc, metaDBChan, dbName, importID)
			done.openssl <- struct{}{}
		}
		done.filesDone <- struct{}{}
	}
}

// startWriters start a fixed number of writer workers for each table to write to
func (writer *writers) startWriters(numWriters int) {
	for i := 0; i < numWriters; i++ {
		writer.ConnTmp.Start(i)
		writer.OpenConnTmp.Start(i)
		writer.DNS.Start(i)
		writer.PDNS.Start(i)
		writer.HTTPTmp.Start(i)
		writer.OpenHTTPTmp.Start(i)
		writer.SSLTmp.Start(i)
		writer.OpenSSLTmp.Start(i)
	}
}

// closeWriters close each writer
func (writer *writers) closeWriters() {
	writer.ConnTmp.Close()
	writer.OpenConnTmp.Close()
	writer.DNS.Close()
	writer.PDNS.Close()
	writer.HTTPTmp.Close()
	writer.OpenHTTPTmp.Close()
	writer.SSLTmp.Close()
	writer.OpenSSLTmp.Close()
}

// season links the http & ssl logs with the conn logs and adds data to those connections
func (importer *Importer) season() error {
	logger := zlog.GetLogger()

	limiter := rate.NewLimiter(5, 5)
	writerWorkers := 2
	sslWriter := database.NewBulkWriter(importer.Database, importer.Cfg, writerWorkers, importer.Database.GetSelectedDB(), "ssl", "INSERT INTO {database:Identifier}.ssl", limiter, false)
	openSSLWriter := database.NewBulkWriter(importer.Database, importer.Cfg, writerWorkers, importer.Database.GetSelectedDB(), "openssl", "INSERT INTO {database:Identifier}.openssl", limiter, false)
	httpWriter := database.NewBulkWriter(importer.Database, importer.Cfg, writerWorkers, importer.Database.GetSelectedDB(), "http", "INSERT INTO {database:Identifier}.http", limiter, false)
	connWriter := database.NewBulkWriter(importer.Database, importer.Cfg, writerWorkers, importer.Database.GetSelectedDB(), "conn", "INSERT INTO {database:Identifier}.conn", limiter, false)
	openHTTPWriter := database.NewBulkWriter(importer.Database, importer.Cfg, writerWorkers, importer.Database.GetSelectedDB(), "openhttp", "INSERT INTO {database:Identifier}.openhttp", limiter, false)
	openConnWriter := database.NewBulkWriter(importer.Database, importer.Cfg, writerWorkers, importer.Database.GetSelectedDB(), "openconn", "INSERT INTO {database:Identifier}.openconn", limiter, false)

	for i := 0; i < writerWorkers; i++ {
		sslWriter.Start(i)
		openSSLWriter.Start(i)
		httpWriter.Start(i)
		openHTTPWriter.Start(i)
		connWriter.Start(i)
		openConnWriter.Start(i)
	}

	linkingErrGroup, ctx := errgroup.WithContext(context.Background())

	gradient := progress.WithGradient("#f67a70", "#ffda6d")

	var barList []*progressbar.ProgressBar
	var spinners []progressbar.Spinner
	sslBarName := "🧂 Seasoning SSL connections "
	httpBarName := "🧂 Seasoning HTTP connections"
	connSpinnerID := 0
	openConnSpinnerID := 0
	const (
		httpID = iota + 1
		openHTTPID
		sslID
		openSSLID
	)

	if importer.ResultCounts.OpenConn > 0 {
		spinners = append(spinners, progressbar.NewSpinner("Sifting open IP connections...", openConnSpinnerID))
		connSpinnerID = 1
		if importer.ResultCounts.OpenSSL > 0 {
			barList = append(barList, progressbar.NewBar("🧂 Seasoning open SSL connections ", openSSLID, progress.New(gradient)))
			sslBarName += "     "
		}
		if importer.ResultCounts.OpenHTTP > 0 {
			barList = append(barList, progressbar.NewBar("🧂 Seasoning open HTTP connections", openHTTPID, progress.New(gradient)))
			httpBarName += "     "
		}
	}

	barList = append(barList,
		progressbar.NewBar(sslBarName, sslID, progress.New(gradient)),
		progressbar.NewBar(httpBarName, httpID, progress.New(gradient)))
	spinners = append(spinners, progressbar.NewSpinner("Sifting IP connections...", connSpinnerID))
	bars := progressbar.New(ctx, barList, spinners)

	linkingErrGroup.Go(func() error {
		_, err := bars.Run()
		if err != nil {
			logger.Error().Err(err).Msg("unable to display progress for connection correlation")
			return fmt.Errorf("unable to display progress for connection correlation: %w", err)
		}
		return err
	})

	linkingErrGroup.Go(func() error {
		err := importer.writeLinkedHTTP(ctx, bars, httpID, httpWriter, connWriter, false)
		if err != nil {
			logger.Error().Err(err).Msg("unable to link http connections")
		}
		return err
	})

	linkingErrGroup.Go(func() error {
		err := importer.writeLinkedSSL(ctx, bars, sslID, sslWriter, false)
		if err != nil {
			logger.Error().Err(err).Msg("unable to link ssl connections")
		}
		return err
	})

	linkingErrGroup.Go(func() error {
		err := importer.writeUnfilteredConns(bars, false, connSpinnerID)
		if err != nil {
			logger.Error().Err(err).Msg("unable to link IP connections")
		}
		return err
	})

	if importer.ResultCounts.OpenConn > 0 {
		linkingErrGroup.Go(func() error {
			err := importer.writeUnfilteredConns(bars, true, openConnSpinnerID)
			if err != nil {
				logger.Error().Err(err).Msg("unable to link open IP connections")
			}
			return err
		})
		if importer.ResultCounts.OpenSSL > 0 {
			linkingErrGroup.Go(func() error {
				err := importer.writeLinkedSSL(ctx, bars, openSSLID, openSSLWriter, true)
				if err != nil {
					logger.Error().Err(err).Msg("unable to link open ssl connections")
				}
				return err
			})
		}
		if importer.ResultCounts.OpenHTTP > 0 {
			linkingErrGroup.Go(func() error {
				err := importer.writeLinkedHTTP(ctx, bars, openHTTPID, openHTTPWriter, openConnWriter, true)
				if err != nil {
					logger.Error().Err(err).Msg("unable to link open http connections")
				}
				return err
			})
		}
	}

	if err := linkingErrGroup.Wait(); err != nil {
		return fmt.Errorf("could not perform connection linking: %w", err)
	}

	sslWriter.Close()
	openSSLWriter.Close()
	httpWriter.Close()
	openHTTPWriter.Close()
	connWriter.Close()
	openConnWriter.Close()

	// // don't truncate tmp tables in debug mode
	// // these tables should be truncated before each import
	if zlog.DebugMode {
		return nil
	}
	return importer.Database.TruncateTmpLinkTables()
}
