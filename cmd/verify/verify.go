// license ..

package main

import (
	"flag"
	"fmt"
	"os"
	"log"
	"net/url"
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

	// a dataFile is specified
	if *dataFile != "" {
		//verifyData(*dataFile)
		panic("NotImplemented")
	// construct a url from the endpoint and page name
	} else {
		u, err := url.Parse(*endpoint + "/" + flag.Args()[0])
		if err != nil {
			log.Fatalln(err)
		}
		//verifyURL(u)
	}
}

func usage() {
	fmt.Println("Usage:\n", "verify [OPTIONS] <page title>\n",
		"or\n", "verify [OPTIONS] --file <offline file.json or file.xml>\n")
	flag.Usage()
}
