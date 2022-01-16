// license ..

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/inblockio/aqua-verifier-go/api"
	"golang.org/x/crypto/sha3"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	verbose   = flag.Bool("v", false, "Verbose")
	endpoint  = flag.String("server", "http://localhost:9352", "<The url of the server, e.g. https://pkc.inblock.io>")
	verify    = flag.Bool("ignore-merkle-proof", false, "Ignore verifying the witness merkle proof of each revision")
	authToken = flag.String("token", "", "(Optional) OAuth2 access token to access the API")
	dataFile  = flag.String("file", "", "(If present) The file to read from for the data")
)

const (
	apiVersion = "0.3.0"
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
	fmt.Printf(`Usage:
verify [OPTIONS] <page title>
or
verify [OPTIONS] --file <offline file.json or file.xml>

`)
	flag.Usage()
}

func verifyData(fileName string) bool {
	data, err := readExportFile(fileName)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if *verbose {
		j, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Fatalf(err.Error())
		}
		fmt.Printf("Decoded input as:\n%s\n", j)
	}

	for _, p := range data.Pages {
		res := verifyPageCLI(p, *verbose, *verify)
		if !res {
			return false
		}
	}
	return true
}

func verifyURL(u *url.URL) bool {
	return false
}

func readExportFile(filename string) (*api.OfflineData, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(strings.ToLower(f.Name()), ".json") {
		d := json.NewDecoder(f)
		data := &api.OfflineData{}
		err := d.Decode(data)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if strings.HasSuffix(strings.ToLower(f.Name()), ".xml") {
		panic("NotImplemented")
	}
	return nil, nil
}

func validateTitle(title string) string {
	var t string
	if strings.Contains(title, "_") {
		t = strings.ReplaceAll(title, "_", " ")
		log.Println("Warning: Underscores in title are converted to spaces.")
	}
	if strings.Contains(t, ": ") {
		log.Println("Warning: Space after ':' detected. You might need to remove it to match MediaWiki title.")
	}
	return t
}

func formatHTTPError(response, message string) {
}

func cliRedify(content string) {
}

func cliYellowfy(content string) {
}

func htmlRedify(content string) {
}

func redify(isHtml, content string) {
}

func htmlDimify(content string) {
}

func log_red(content string) {
}

func log_yellow(content string) {
}

func log_dim(content string) {
}

func formatMwTimestamp(ts time.Time) {
}

func formatDBTimestamp(ts time.Time) {
}

func getElapsedTime(start time.Time) {
}

func shortenHash(hash string) {
}

func clipboardifyHash(hash string) {
}

func makeHref(content string, u *url.URL) {
}

func getHashSum(content string) string {
	// XXX: do we want to encode the output in something human parsable such as base64 ?
	s := sha3.Sum512([]byte(content))
	return hex.EncodeToString(s[:])
}

func calculateMetadataHash(domainId, timestamp, previousVerificationHash string) string {
	return getHashSum(domainId + timestamp + previousVerificationHash)
}

func calculateSignatureHash(signature string, publicKey string) string {
	// XXX: what is the publckey format ?
	return getHashSum(signature + publicKey)
}

func calculateWitnessHash(domain_snapshot_genesis_hash, merkle_root, witness_network, witness_tx_hash string) []byte {
	panic("NotImplemented")
	return nil
}

func calculateVerificationHash(contentHash, metadataHash, signature_hash, witness_hash string) string {
	return getHashSum(contentHash + metadataHash + signature_hash + witness_hash)
}

func checkAPIVersionCompatibility(ap *api.AquaProtocol) bool {
	s, err := ap.GetServerInfo()
	if err != nil {
		log.Println("Unable to query server info:", err)
	} else if s.ApiVersion == apiVersion {
		return true
	}
	return false
}

func verifyMerkleIntegrity(merkleBranch string, verificationHash string) bool {
	panic("NotImplemented")
	return false
}

func verifyWitness() {
}

func printRevisionInfo(revision *api.Revision) {
}

func verifyFile(data []byte) bool {
	panic("NotImplemented")
	return false
}

func formatRevisionInfo2HTML(server *api.ServerInfo, detail *api.Revision, verbose bool) {
}

func formatPageInfo2HTML(serverUrl string, title string, status int, details string, verbose bool) {
}

func verifyRevision(*api.Revision) bool {
	//vh
	//revisionInput
	//previousVerification
	//doVerifyMerkleProof
	return true
}

func calculateStatus(count, totalLength int) {
}

func verifyPage(page *api.RevisionInfo, verbose bool, doVerifyMerkleProof bool, token string) bool {
	panic("NotImplemented")
	return false
}

// verifyPage verifies all revisions of a page.
func verifyPageCLI(page *api.RevisionInfo, verbose bool, doVerifyMerkleProof bool) bool {

	// start with the latest revision, and verify each revision until we reach the genesis
	rh := page.LatestVerificationHash

	for height := page.ChainHeight - 1; height >= 0; height-- {
		r, ok := page.Revisions[rh]
		if !ok {
			log.Println("Failed to find previous revision")
			return false
		}
		if !verifyRevision(r) {
			log.Printf("Failed to verify revision %s", rh)
			panic("wtf")
			return false
		}
		dId := r.Metadata.DomainId
		if dId != page.DomainId {
			log.Printf("Inconsistent domainId in Revision %s", rh)
			return false
		}
		ts := r.Metadata.Timestamp.String()
		fmt.Println(ts)
		ph := r.Metadata.PreviousVerificationHash

		mh := calculateMetadataHash(dId, ts, ph)
		if mh != r.Metadata.MetadataHash {
			log.Printf("MetadataHash does not match in revision %s", rh)
			log.Println("Calculated:" + mh)
			log.Println("Previous:" + r.Metadata.MetadataHash)
			return false
		}
		fmt.Printf("h: %d\n", height)
		fmt.Printf("rh: %s\n", rh)
		rh = r.Metadata.PreviousVerificationHash
		if rh == "" && height == 0 {
			if r.Metadata.VerificationHash != page.GenesisHash {
				log.Println("Failed to reach genesis revision!")
				return false
			}
			return true
		}
	}
	return false
}

/*
func makeSureAlwaysArray(x) {
}
*/

func transformMwXmlRevision2PkcJson(rev *api.Revision) {
	panic("NotImplemented")
}

func transformRevisions(revisions []*api.Revision) {
	panic("NotImplemented")
}

func parseMWXmlString(fileContent []byte) {
	panic("NotImplemented")
}
