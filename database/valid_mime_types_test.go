package database

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// go test -v ./database -run TestReadValidTextMIMETypeFile
func TestReadValidTextMIMETypeFile(t *testing.T) {

	tests := []struct {
		name              string
		dataCSV           string
		writeChan         chan Data
		expectedMIMETypes []*ValidMIMEType
		expectedTotal     int
		expectedError     bool
	}{

		{
			name: "Simple",
			dataCSV: `a,b,c,d
					  1,2,3,4`,
			writeChan: make(chan Data),
			expectedMIMETypes: []*ValidMIMEType{
				{
					MIMEType:  "b",
					Extension: "c",
				},
				{
					MIMEType:  "2",
					Extension: "3",
				},
			},
			expectedTotal: 2,
			expectedError: false,
		},

		{
			name: "Valid MIME type file",
			dataCSV: `css,text/css,.css,[RFC2318]
					  csv,text/csv,.csv,[RFC4180][RFC7111]`,
			writeChan: make(chan Data),
			expectedMIMETypes: []*ValidMIMEType{
				{
					MIMEType:  "text/css",
					Extension: "css",
				},
				{
					MIMEType:  "text/csv",
					Extension: "csv",
				},
			},
			expectedTotal: 2,
			expectedError: false,
		},
		{
			name: "Test for Multiple Extensions",
			dataCSV: `plain,text/plain,".txt, .ps",[RFC2046][RFC3676][RFC5147]
					  markdown,text/markdown,".md, .markdown",[RFC7763]
					  javascript,text/javascript,".js, .mjs., es, .mjs",[RFC9239]
					  html,text/html,none,[RFC21221]`,
			writeChan: make(chan Data),
			expectedMIMETypes: []*ValidMIMEType{
				{
					MIMEType:  "text/plain",
					Extension: "txt",
				},
				{
					MIMEType:  "text/plain",
					Extension: "ps",
				},
				{
					MIMEType:  "text/markdown",
					Extension: "md",
				},
				{
					MIMEType:  "text/markdown",
					Extension: "markdown",
				},
				{
					MIMEType:  "text/javascript",
					Extension: "js",
				},
				{
					MIMEType:  "text/javascript",
					Extension: "mjs",
				},
				{
					MIMEType:  "text/javascript",
					Extension: "es",
				},
				{
					MIMEType:  "text/javascript",
					Extension: "mjs",
				},
				{
					MIMEType:  "text/html",
					Extension: "",
				},
			},
			expectedTotal: 9,
			expectedError: false,
		},
		{
			name: "Valid File with an Entry with Empty MIME Type",
			dataCSV: `css,text/css,.css,[RFC2318]
					  csv,text/csv,.csv,[RFC4180][RFC7111]
					  ,,.txt,[RFC2046][RFC3676][RFC5147]`,
			writeChan: make(chan Data),
			expectedMIMETypes: []*ValidMIMEType{
				{
					MIMEType:  "text/css",
					Extension: "css",
				},
				{
					MIMEType:  "text/csv",
					Extension: "csv",
				},
			},
			expectedTotal: 2,
			expectedError: false,
		},
		{
			name: "Invalid MIME type file - less than 4 columns",
			dataCSV: `a,b,c
					  1,2,3`,
			writeChan:         make(chan Data),
			expectedMIMETypes: []*ValidMIMEType{},
			expectedTotal:     0,
			expectedError:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// require := require.New(t)

			// create a temporary file to read from
			tmpFile, err := os.CreateTemp("", "test-mime-types-*.csv")
			require.NoError(t, err, "reading from temporary file should not produce an error")

			// clean up after the test
			defer os.Remove(tmpFile.Name())

			// write the CSV to temporary file
			_, err = tmpFile.Write([]byte(test.dataCSV))
			require.NoError(t, err, "writing to temporary file should not produce an error")
			require.NotEmpty(t, tmpFile, "temporary file should not be empty")

			// close temporary file
			err = tmpFile.Close()
			require.NoError(t, err, "closing temporary file should not produce an error")

			wg := sync.WaitGroup{}
			wg.Add(1)
			total := 0
			go func(writeChan chan Data, expectedMIMETypes []*ValidMIMEType) {
				defer wg.Done()
				for entry := range writeChan {
					// cast entry to ValidMIMEType
					validMIMEType, ok := entry.(*ValidMIMEType)
					assert.True(t, ok, "entry should be of type *ValidMIMEType")

					// check if the MIME type is in the list of expected MIME types
					assert.Contains(t, expectedMIMETypes, validMIMEType, "MIME type should be in the list of expected MIME types")

					total++
				}
			}(test.writeChan, test.expectedMIMETypes)

			// run the function
			err = readValidTextMIMETypeFile(tmpFile.Name(), test.writeChan)

			// check if the error is as expected
			require.Equal(t, test.expectedError, err != nil, "error should match expected value")

			// close the write channel and wait for the goroutine to finish
			close(test.writeChan)
			wg.Wait()

			// check if the total number of MIME types is as expected
			require.Equal(t, test.expectedTotal, total, "total number of MIME types should match expected value")

		})
	}

}
