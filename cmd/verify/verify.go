// license ..

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/inblockio/aqua-verifier-go/api"
	"github.com/inblockio/aqua-verifier-go/verify"
)

var (
	verbose           = flag.Bool("v", false, "Verbose")
	endpoint          = flag.String("server", "http://localhost:9352", "<The url of the server, e.g. https://pkc.inblock.io>")
	ignoreMerkleProof = flag.Bool("ignore-merkle-proof", false, "Ignore verifying the witness merkle proof of each revision")
	authToken         = flag.String("token", "", "(Optional) OAuth2 access token to access the API")
	dataFile          = flag.String("file", "", "(If present) The file to read from for the data")
	depth             = flag.Int("depth", -1, "(Optional) Depth to follow verification chain. By default, verifies all revisions")
	ap                *api.AquaProtocol
)

func main() {

	flag.Parse()
	// neither a file nor a page title was specified
	if len(flag.Args()) == 0 && *dataFile == "" {
		usage()
		os.Exit(-1)
	}

	verify.Verbose = *verbose

	if *dataFile != "" {
		// a dataFile is specified
		if verify.VerifyData(*dataFile, *ignoreMerkleProof, *depth) {
			fmt.Println("Verified:", *dataFile)
		} else {
			fmt.Println("Failed to verify:", *dataFile)
		}
	} else {
		// else construct a url from the endpoint and page name
		title := flag.Args()[0]
		a, e := api.NewAPI(*endpoint, *authToken)
		if e != nil {
			fmt.Println("Failed to get api endpoint", e)
			os.Exit(-1)
		}
		if verify.VerifyPage(a, title, true, *depth) {
			fmt.Println("Verified:", title)
		} else {
			fmt.Println("Failed to verify:", title)
		}
	}
}

func usage() {
	fmt.Printf(`Usage:
verify [OPTIONS] <page title>
or
verify [OPTIONS] --file <offline file.json or file.xml>

`)
	flag.Usage()
}
