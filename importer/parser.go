package importer

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	zerolog "github.com/activecm/rita/logger"
	"github.com/activecm/rita/util"

	jsoniter "github.com/json-iterator/go"
	"github.com/spf13/afero"
)

var errTruncated = errors.New("log file is potentially truncated")
var errUnknownFileType = errors.New("failed to parse log file: unknown file type or malformed header")
var errMismatchedPathField = errors.New("TSV 'path' field does not match file pathname prefix")

// ZeekHeader stores vars in the header of the zeek log
type ZeekHeader[Z zeekRecord] struct {
	separator             string
	setSeparator          string
	emptyField            string
	unsetField            string
	path                  string
	open                  time.Time
	fieldOrder            []string
	rawFields             string
	rawTypes              string
	isTSV                 bool
	isJSON                bool
	headerToStructMapping map[string]int
	fsPath                string // actual file system path of log
}

type MetaDBFile struct {
	importID util.FixedString
	database string
	fileHash util.FixedString
	path     string
}

// ZeekDateTimeFmt is the common format for zeek header datetimes
const ZeekDateTimeFmt = "2006-01-02-15-04-05"

const ConnPrefix = "conn"
const OpenConnPrefix = "open_conn"
const DNSPrefix = "dns"
const HTTPPrefix = "http"
const OpenHTTPPrefix = "open_http"
const SSLPrefix = "ssl"
const OpenSSLPrefix = "open_ssl"
const ConnSummaryPrefixUnderscore = "conn_summary"
const ConnSummaryPrefixHyphen = "conn-summary"

const lineErrorLimit = 25

// parseFile is a generic function that determines if a passed in path belongs to a tsv or json file, parses the file header and scans through each subsequent line,
// parsing/unmarshaling it into its associated zeektype and sending it on the passed in generic channel. The generic type is based on the path's prefix in the calling
// function.
func parseFile[Z zeekRecord](afs afero.Fs, path string, entryChan chan<- Z, errc chan<- error, metaDBChan chan<- MetaDBFile, database string, importID util.FixedString) {
	logger := zerolog.GetLogger()

	// open file for reading
	empty, err := afero.IsEmpty(afs, path)
	if err != nil {
		logger.Err(err).Str("path", path).Msg("could not determine if file is empty")
		return
	}

	// skip file if it is empty and log a warning
	if empty {
		logger.Warn().Str("path", path).Msg("failed to parse log file: file is empty")
		return
	}

	file, err := afs.Open(path)
	if err != nil {
		logger.Err(err).Str("path", path).Msg("could not open file for parsing")
		return
	}
	defer file.Close()

	fileHash, err := util.NewFixedStringHash(path)
	if err != nil {
		logger.Err(err).Str("path", path).Msg("could not hash file path")
		return
	}

	metaDBFileEntry := MetaDBFile{
		importID: importID,
		database: database,
		fileHash: fileHash,
		path:     path,
	}

	// set up a new scanner to read from file
	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		// create gzip reader if the file extension insinuates that the file is compressed
		gzipReader, err := gzip.NewReader(file)
		if err != nil { // handle error from scanner
			logger.Err(err).Str("path", path).Msg("failed to parse log file: could not open compressed file")
			return
		}
		scanner = bufio.NewScanner(gzipReader)
		defer gzipReader.Close()
	} else {
		scanner = bufio.NewScanner(file)
	}

	// set a buffer for the scanner
	initialBufferSize := 64 * 1024 // 64KiB
	maxBufferSize := 1024 * 1024   // 1MiB
	scanner.Buffer(make([]byte, 0, initialBufferSize), maxBufferSize)

	// declare new header object for parsing tsv headers
	var header ZeekHeader[Z]
	header.headerToStructMapping = make(map[string]int)

	var typeArr []string

	// declare a generic log entry object
	var entry Z

	// create line error counter which will allow us to stop scanning in lines from
	// a file that had more than a certain amount of errors
	lineErrorCounter := 0

	previousLineHadError := false

	// iterate over lines in file
	for scanner.Scan() {
		// handle error from scanner
		if scanner.Err() != nil {
			logger.Err(err).Str("path", path).Msg("failed to parse log file: could not scan the file")
			return
		}

		// skip empty lines
		if len(scanner.Bytes()) < 1 {
			continue
		}

		// if header type has not been set, attempt to determine log format
		if !header.isJSON && !header.isTSV {

			switch {

			// Since this line is a comment (it starts with a #), try to parse header in tsv format
			case scanner.Bytes()[0] == '#':
				// there are multiple comment lines that make up the header, so we need to call this function
				// several times until the lines we scan are no longer comments in order to populate the header info
				typeArr, err = header.parseHeader(scanner.Text())

				// return since parsing of tsv header failed and file is not json
				if err != nil {
					logger.Error().Err(err).Str("path", path).Msg("failed to parse log file: unable to parse TSV Zeek header")
					return
				}

			// Since the line does not begin with a comment, attempt to check if it is json
			case scanner.Bytes()[0] == '{' && jsoniter.ConfigCompatibleWithStandardLibrary.Valid(scanner.Bytes()):
				header.isJSON = true
				metaDBChan <- metaDBFileEntry

			// Line is not JSON and is not a comment
			default:
				// check if tsv header was parsed successfully
				if header.separator != "" && len(header.fieldOrder) > 0 {

					// set the isTSV header field to true and map the names of the header fields to the struct.
					header.isTSV = true

					// check & warn if path field doesn't match filename prefix
					header.fsPath = path
					err := header.validatePathPrefix()
					if err != nil {
						logger.Error().Str("path", path).Err(err).Send()
					}
					err = header.mapHeader()

					// return since mapping of tsv header failed and file is not json
					if err != nil {
						logger.Err(err).Str("path", path).Msg("failed to parse log file: could not detect valid TSV Zeek header, is file valid TSV or JSON?")
						return
					}
					metaDBChan <- metaDBFileEntry

					// if no header fields were found, quit parsing this file
				} else {
					logger.Err(errUnknownFileType).Str("path", path).Send()
					errc <- errUnknownFileType
					return
				}
			}
		}

		// parse this line as JSON if we've determined this file is in JSON format
		if header.isJSON {
			previousLineHadError = false
			// unmarshal line
			if err := jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal(scanner.Bytes(), &entry); err != nil {
				logger.Err(err).Str("path", path).Bytes("record", scanner.Bytes()).Msg("failed to unmarshal line from JSON")
				lineErrorCounter++
				previousLineHadError = true
				if lineErrorCounter > lineErrorLimit {
					logger.Warn().Str("path", path).Msg("failed to parse log file: file is potentially corrupted")
					// set this flag to false so that we don't log that this file could be truncated
					previousLineHadError = false
					break
				}
				continue
			}

			// set log path field
			data := reflect.ValueOf(&entry).Elem()
			data.FieldByName("LogPath").SetString(path)

			// send parsed entry to its appropriate channel
			entryChan <- entry

			resetZeekRecord(&entry)

			// parse this line as TSV if we've determined this file is in TSV format
		} else if header.isTSV {
			previousLineHadError = false

			// don't parse this line if it is a comment
			if scanner.Bytes()[0] == '#' {
				continue
			}
			// get the type of zeek log record this entry is
			data := reflect.ValueOf(&entry).Elem()

			// reset the entry just to be safe
			data.Set(reflect.Zero(data.Type()))

			// scan in line
			line := scanner.Text()

			// track whether or not this line had an error when parsing any fields
			lineHadError := false

			// set the end index of the field itself to the index of the next tab (or separator)
			fieldEndIndex := strings.Index(line, header.separator)

			// set field counter
			idx := 0

			// loop through all but last fields in line
			for fieldEndIndex > -1 && idx < len(header.fieldOrder) {

				// check if the header field is in the struct
				if header.headerToStructMapping[header.fieldOrder[idx]] > -1 {
					// parse field if not empty or unset
					if line[:fieldEndIndex] != header.emptyField && line[:fieldEndIndex] != header.unsetField {

						// parse field by assigning the correlating struct field using reflection
						err := header.parseField(
							line[:fieldEndIndex], // the field itself, sliced out of the line
							typeArr[idx],         // the zeek type of the field
							data.Field(header.headerToStructMapping[header.fieldOrder[idx]])) // the struct field to update

						if err != nil {
							logger.Warn().Err(err).
								Str("path", path).
								Str("field_name", header.fieldOrder[idx]).
								Str("field_value", line).
								Msg("failed to parse field in TSV Zeek log")
							lineHadError = true
							previousLineHadError = true
						}
					}

				}
				// reslice line to first of next field to the end of the line
				line = line[fieldEndIndex+len(header.separator):]

				// update the end index of the field to the index of the next tab (or separator)
				fieldEndIndex = strings.Index(line, header.separator)
				idx++
			}

			if fieldEndIndex == -1 && idx < len(header.fieldOrder)-2 {
				logger.Err(errTruncated).Str("path", path).Send()
				errc <- errTruncated
				break
			}

			// parse in last field
			if idx < len(header.fieldOrder) && line != header.emptyField && line != header.unsetField &&
				header.headerToStructMapping[header.fieldOrder[idx]] > -1 {
				err := header.parseField(
					line,         // the last field, now the only thing left in line
					typeArr[idx], // the zeek type of the field
					data.Field(header.headerToStructMapping[header.fieldOrder[idx]])) // the struct field to update

				if err != nil {
					logger.Warn().Err(err).
						Str("path", path).
						Str("field_name", header.fieldOrder[idx]).
						Str("field_value", line).
						Msg("failed to parse field in TSV Zeek log")
					lineHadError = true
					previousLineHadError = true
				}
			}

			// increment file parsing error count if there were errors during field parsing
			if lineHadError {
				lineErrorCounter++
			}

			// return if parsing error limit for file was reached
			if lineErrorCounter > lineErrorLimit {
				logger.Warn().Str("path", path).Msg("log file is potentially corrupted")
				// set this flag to false so that we don't log that this file could be truncated
				previousLineHadError = false
				break
			}

			// set log path field
			data.FieldByName("LogPath").SetString(path)

			// send parsed entry to its appropriate channel
			entryChan <- entry

			// reset the zeek record entry just in case
			resetZeekRecord(&entry)
		}
	}

	// if last line of log had an error, indicate that file may be truncated
	if previousLineHadError {
		logger.Err(errTruncated).Str("path", path).Send()
		errc <- errTruncated
	}
}

// parseHeader parses the header of a Zeek log in TSV format
func (header *ZeekHeader[Z]) parseHeader(line string) (typeArr []string, err error) {

	potentialFields := strings.Fields(line)
	// 	grabs from the comment # to the space to get the first field value
	potentialFieldName := potentialFields[0][1:]
	potentialFieldValue := convertHexFieldValue(potentialFields[1])

	switch potentialFieldName {
	case "separator":
		header.separator = potentialFieldValue
	case "set_separator":
		header.setSeparator = potentialFieldValue
	case "unset_field":
		header.unsetField = potentialFieldValue
	case "path":
		header.path = potentialFieldValue
	case "empty_field":
		header.emptyField = potentialFieldValue
	case "open":
		var dateParseErr error
		header.open, dateParseErr = time.Parse(ZeekDateTimeFmt, potentialFieldValue)
		if dateParseErr != nil {
			return nil, fmt.Errorf("date not parsed for open field: %v", dateParseErr.Error())
		}
	case "fields":
		header.rawFields = line
	case "types":
		header.rawTypes = line
	}
	// 	map zeek fields and types, get field order
	if len(header.rawFields) > 0 && len(header.rawTypes) > 0 {
		splitFields := strings.Fields(header.rawFields)
		splitTypes := strings.Fields(header.rawTypes)

		splitFields = splitFields[1:]
		splitTypes = splitTypes[1:]

		if len(splitTypes) == len(splitFields) {
			typeArr = make([]string, len(splitFields))
			for idx := range splitFields {
				// track the field names by the order they appear in the header
				header.fieldOrder = append(header.fieldOrder, splitFields[idx])
				// track the field types by the order they appear in the header
				typeArr[idx] = splitTypes[idx]
			}
			return typeArr, nil
		}

		return nil, fmt.Errorf("mismatched header fields. zeek types: %v, zeek fields: %v", splitTypes, splitFields)
	}

	return typeArr, nil
}

// mapHeader maps the names of the fields found in the log header to the corresponding
// struct field's "index". This allows the struct to be dynamically populated using reflection.
func (header *ZeekHeader[Z]) mapHeader() error {
	// creates an empty object of the generic type so that reflect can determine which
	// log type we are dealing with
	var entry Z
	structType := reflect.TypeOf(entry)

	// walk the fields of the zeekData, making sure the zeekData struct has
	// an equal number of named zeek fields and zeek types
	for i := 0; i < structType.NumField(); i++ {
		structField := structType.Field(i)
		zeekName := structField.Tag.Get("zeek")
		zeekType := structField.Tag.Get("zeektype")

		// If this field is not associated with zeek, skip it
		if len(zeekName) == 0 && len(zeekType) == 0 {
			continue
		}

		if len(zeekName) == 0 || len(zeekType) == 0 {
			return errors.New("invalid zeek field")
		}

		header.headerToStructMapping[zeekName] = i

	}

	// Make sure that fields that are in the header and not in the struct definition get ignored
	// walks the fields of the header and sets the mapping for any header fields that are not
	// in the struct to a -1, otherwise looking up the map will return a 0 which will break parsing
	for _, headerName := range header.fieldOrder {
		if _, ok := header.headerToStructMapping[headerName]; !ok {
			header.headerToStructMapping[headerName] = -1
		}
	}

	return nil
}

// parseField parses a single field in a zeek log record
func (header *ZeekHeader[Z]) parseField(value string, zeekType string, resultField reflect.Value) error {
	// handle data cleaning / conversion for the different zeek types
	switch zeekType {
	case "time":
		decimalPointIdx := strings.Index(value, ".")
		if decimalPointIdx == -1 {
			return fmt.Errorf("couldn't convert unix ts: no decimal point in timestamp: %v", value)
		}

		s, err := strconv.Atoi(value[:decimalPointIdx])
		if err != nil {
			return fmt.Errorf("couldn't convert unix ts: %v", err.Error())
		}

		nanos, err := strconv.Atoi(value[decimalPointIdx+1:])
		if err != nil {
			return fmt.Errorf("couldn't convert unix ts: %v", err.Error())
		}

		ttim := time.Unix(int64(s), int64(nanos))
		tval := ttim.Unix()
		resultField.SetInt(tval)
	case "interval":
		intervalFloat, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return fmt.Errorf("couldn't convert zeektype interval: %v", err.Error())
		}
		tval := reflect.ValueOf(intervalFloat)
		resultField.Set(tval)
	case "string":
		fallthrough
	case "enum":
		fallthrough
	case "addr":
		resultField.SetString(value)
	case "count":
		countInt, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return fmt.Errorf("couldn't convert zeektype count: %v", err.Error())
		}
		resultField.SetInt(countInt)
	case "port":
		portInt, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("couldn't convert zeektype port: %v", err.Error())
		}
		resultField.SetInt(int64(portInt))
	case "bool":
		boolCvt, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("couldn't convert zeektype bool: %v", err.Error())
		}
		resultField.SetBool(boolCvt)
	case "set[string]":
		fallthrough
	case "set[enum]":
		fallthrough
	case "vector[string]":
		strsSplit := strings.Split(value, header.setSeparator)
		tval := reflect.ValueOf(strsSplit)
		resultField.Set(tval)
	case "vector[interval]":
		var intervals []float64
		strNums := strings.Split(value, header.setSeparator)
		for _, str := range strNums {
			intervalFloat, err := strconv.ParseFloat(strings.TrimSpace(str), 64)
			if err != nil {
				return fmt.Errorf("couldn't convert zeektype: vector[interval] %w", err)
			}
			intervals = append(intervals, intervalFloat)
		}
		tval := reflect.ValueOf(intervals)
		resultField.Set(tval)
	default:
	}

	return nil
}

// validatePathPrefix returns an error if the TSV header path field does not match the prefix of the file's path name
func (header *ZeekHeader[Z]) validatePathPrefix() (err error) {
	switch {
	case strings.HasPrefix(filepath.Base(header.fsPath), ConnPrefix) && !strings.HasPrefix(filepath.Base(header.fsPath), ConnSummaryPrefixUnderscore) && !strings.HasPrefix(filepath.Base(header.fsPath), ConnSummaryPrefixHyphen):
		if header.path != ConnPrefix {
			return errMismatchedPathField
		}
	case strings.HasPrefix(filepath.Base(header.fsPath), OpenConnPrefix):
		if header.path != OpenConnPrefix {
			return errMismatchedPathField
		}
	case strings.HasPrefix(filepath.Base(header.fsPath), DNSPrefix):
		if header.path != DNSPrefix {
			return errMismatchedPathField
		}
	case strings.HasPrefix(filepath.Base(header.fsPath), HTTPPrefix):
		if header.path != HTTPPrefix {
			return errMismatchedPathField
		}
	case strings.HasPrefix(filepath.Base(header.fsPath), OpenHTTPPrefix):
		if header.path != OpenHTTPPrefix {
			return errMismatchedPathField
		}
	case strings.HasPrefix(filepath.Base(header.fsPath), SSLPrefix):
		if header.path != SSLPrefix {
			return errMismatchedPathField
		}
	case strings.HasPrefix(filepath.Base(header.fsPath), OpenSSLPrefix):
		if header.path != OpenSSLPrefix {
			return errMismatchedPathField
		}
	}
	return nil
}

// convertHexFieldValue converts any hex encoded zeek field values to normal characters
// if err is true, conversion was not needed and original value is returned
// ie: tab char = \x09
func convertHexFieldValue(givenValue string) string {
	newValue, err := strconv.Unquote("\"" + givenValue + "\"")
	if err != nil {
		return givenValue
	}
	return newValue
}

// resetZeekRecord resets the zeek record with values that represent zero
func resetZeekRecord(r any) {
	p := reflect.ValueOf(r).Elem()
	p.Set(reflect.Zero(p.Type()))
}
