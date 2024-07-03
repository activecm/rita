package database

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/activecm/rita/v5/config"
	"github.com/activecm/rita/v5/util"

	"github.com/spf13/afero"
	"golang.org/x/time/rate"
)

type ValidMIMEType struct {
	MIMEType  string `ch:"mime_type"`
	Extension string `ch:"extension"`
}

// createValidMIMETypeTable creates a table that stores MIME types beginning with "text" (text/css) and their associated extensions
func (server *ServerConn) createValidMIMETypeTable() error {
	err := server.Conn.Exec(server.ctx, `
		DROP TABLE IF EXISTS metadatabase.valid_mime_types
	`)
	if err != nil {
		return err
	}
	err = server.Conn.Exec(server.ctx, `
		CREATE TABLE IF NOT EXISTS metadatabase.valid_mime_types (
			mime_type String,
			extension String
		) ENGINE = MergeTree()
		PRIMARY KEY (mime_type)
	`)

	return err

}

func (server *ServerConn) importValidMIMETypes(afs afero.Fs, cfg *config.Config) error {
	// create a rate limiter to control the rate of writing to the database
	limiter := rate.NewLimiter(5, 5)

	// create a channel to write mime type entries to the database
	writer := NewBulkWriter(server, cfg, 1, "metadatabase", "valid_mime_types", "INSERT INTO metadatabase.valid_mime_types", limiter, false)
	writer.Start(0)

	extFile, err := util.ParseRelativePath(cfg.HTTPExtensionsFilePath)
	if err != nil {
		return err
	}
	if err := readValidTextMIMETypeFile(extFile, writer.WriteChannel); err != nil {
		return err
	}

	writer.Close()

	return nil
}

func readValidTextMIMETypeFile(filePath string, writeChan chan Data) error {
	file, err := os.Open(filePath)

	// Checks for the error
	if err != nil {

		log.Fatal("Error while reading the file", err)
		return err
	}

	// Closes the file
	defer file.Close()

	// The csv.NewReader() function is called in
	// which the object os.File passed as its parameter
	// and this creates a new csv.Reader that reads
	// from the file
	reader := csv.NewReader(file)

	// ReadAll reads all the records from the CSV file
	// and Returns them as slice of slices of string
	// and an error if any
	records, err := reader.ReadAll()

	// Checks for the error
	if err != nil {
		fmt.Println("Error reading records")
		return err
	}

	// Loop to iterate through
	// and print each of the string slice
	for _, line := range records {
		if len(line) < 4 {
			return errors.New("valid MIME type CSV does not contain at least 4 columns")
		}
		mimeType := line[1]
		if len(mimeType) < 1 {
			continue
		}
		extension := line[2]

		if extension == "none" {
			extension = ""
		}

		// remove dots from extension names
		extension = strings.ReplaceAll(extension, ".", "")

		// if extensions is a list, create a row for each one
		extensions := strings.Split(extension, ",")
		if len(extensions) > 1 {
			for _, ext := range extensions {

				ext = strings.TrimSpace(ext)
				if len(ext) > 0 {
					entry := &ValidMIMEType{
						MIMEType:  mimeType,
						Extension: ext,
					}
					writeChan <- entry
				}
			}
		} else {
			entry := &ValidMIMEType{
				MIMEType:  mimeType,
				Extension: extension,
			}
			writeChan <- entry
		}
	}
	return nil
}
