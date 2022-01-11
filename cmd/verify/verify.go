// license ..

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

var (
	verbose   = flag.String("v", "", "Verbose")
	endpoint  = flag.String("server", "http://localhost:9352", "<The url of the server, e.g. https://pkc.inblock.io>")
	verify    = flag.Bool("ignore-merkle-proof", false, "Ignore verifying the witness merkle proof of each revision")
	authToken = flag.String("token", "", "(Optional) OAuth2 access token to access the API")
	dataFile  = flag.String("file", "", "(If present) The file to read from for the data")
)

func main() {

	flag.Parse()
	// neither a file nor a page title was specified
	if len(flag.Args()) == 0 && *dataFile == "" {
		usage()
		os.Exit(-1)
	}

	if *dataFile != "" {
		// a dataFile is specified
		if verifyData(*dataFile) {
			fmt.Println("Verified:", *dataFile)
		} else {
			fmt.Println("Failed to verify:", *dataFile)
		}
	} else {
		// else construct a url from the endpoint and page name
		u, err := url.Parse(*endpoint + "/" + flag.Args()[0])
		if err != nil {
			log.Fatalln(err)
		}
		if verifyURL(u) {
			fmt.Println("Verified:", u)
		} else {
			fmt.Println("Failed to verify:", u)
		}
	}
}

func usage() {
	fmt.Println("Usage:\n", "verify [OPTIONS] <page title>\n",
		"or\n", "verify [OPTIONS] --file <offline file.json or file.xml>\n")
	flag.Usage()
}

type offlineData struct {
	pages []pageData
}

type pageData struct {
	title string
	body  string
}

func verifyData(fileName string) bool {
	_, err := readExportFile(fileName)
	if err != nil {
		panic(err)
	}
	return false
}

func verifyURL(u *url.URL) bool {
	return false
}

func readExportFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
		d := json.NewDecoder(f)
		data := &offlineData{}
		err := d.Decode(data)
		if err != nil {
			return nil, err
		}
	}
	if strings.HasSuffix(strings.ToLower(f.Name()), ".xml") {
		panic("NotImplemented")
	}
	return nil, nil
}
