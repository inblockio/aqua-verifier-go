// license ..

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/sha3"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	verbose   = flag.String("v", "", "Verbose")
	endpoint  = flag.String("server", "http://localhost:9352", "<The url of the server, e.g. https://pkc.inblock.io>")
	verify    = flag.Bool("ignore-merkle-proof", false, "Ignore verifying the witness merkle proof of each revision")
	authToken = flag.String("token", "", "(Optional) OAuth2 access token to access the API")
	dataFile  = flag.String("file", "", "(If present) The file to read from for the data")

	apiClient = &http.Client{}
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
	// TODO: figure out what this format is
}

type revisionHash struct {
	// TODO: figure out what this format is
}

type revisionData struct {
	// TODO: figure out what this format is
	version   string
	title     string
	revisions []revisionHash
}

/*
types nameSpace, siteInfo, and hashChainInfo derived from API response from
http://localhost:9352/rest.php/data_accounting/get_hash_chain_info/title/Main_Page
*/

type nameSpace struct {
	ncase bool `json:"case"`
	title string
}

type siteInfo struct {
	sitename   string
	dbname     string
	base       *url.URL
	generator  string
	ncase      bool `json:"case"`
	namespaces map[int]*nameSpace
}

type hashChainInfo struct {
	genesis_hash             string
	domain_id                string
	latest_verification_hash string
	site_info                *siteInfo
	title                    string
	namespace                int
	chain_height             int
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

func validateTitle(title string) string {
	return ""
}

func getApiURL(server string) *url.URL {
	panic("NotImplemented")
	return nil
}

type serverInfo struct {
	api_version string
}

func getServerInfo(server string) *serverInfo {
	u, err := url.Parse(server + "/rest.php/data_accounting/get_server_info")
	if err != nil {
		log.Println(err)
		return nil
	}
	resp, err := http.Get(u.String())
	if err != nil {
		log.Println(err)
		return nil
	}
	d := json.NewDecoder(resp.Body)
	s := new(serverInfo)
	err = d.Decode(s)
	if err != nil {
		log.Println(err)
		return nil
	}
	return s
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

func getHashSum(content string) []byte {
	// XXX: do we want to encode the output in something human parsable such as base64 ?
	s := sha3.Sum512([]byte(content))
	return s[:]
}

func calculateMetadataHash(domainId, timestamp, previousVerificationHash string) []byte {
	return getHashSum(domainId + timestamp + previousVerificationHash)
}

func calculateSignatureHash(signature string, publicKey string) []byte {
	// XXX: what is the publckey format ?
	return getHashSum(signature + publicKey)
}

func calculateWitnessHash(domain_snapshot_genesis_hash, merkle_root, witness_network, witness_tx_hash string) []byte {
	panic("NotImplemented")
	return nil
}

func calculateVerificationHash(contentHash, metadataHash, signature_hash, witness_hash string) []byte {
	return getHashSum(contentHash + metadataHash + signature_hash + witness_hash)
}

func fetchWithToken(u *url.URL, token string) (*http.Response, error) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer"+token)
	return apiClient.Do(req)
}

func getRevisionHashes(apiURL *url.URL, title string, token string) *hashChainInfo {
	u, err := url.Parse(apiURL.String() + "/" + "get_hash_chain_info/title" + title)
	if err != nil {
		log.Println(err)
		return nil
	}
	resp, err := fetchWithToken(u, token)
	if err != nil {
		log.Println(err)
		return nil
	}
	d := json.NewDecoder(resp.Body)
	h := new(hashChainInfo)
	err = d.Decode(h)
	if err != nil {
		log.Println(err)
		return nil
	}
	return h
}

func checkAPIVersionCompatibility(server string) {
}

func verifyMerkleIntegrity(merkleBranch string, verificationHash string) bool {
	panic("NotImplemented")
	return false
}

func verifyWitness() {
}

func printRevisionInfo(detail string) {
}

func verifyFile(data []byte) bool {
	panic("NotImplemented")
	return false
}

func formatRevisionInfo2HTML(server string, detail string, verbose bool) {
}

func formatPageInfo2HTML(serverUrl string, title string, status int, details string, verbose bool) {
}

func verifyRevision() {
}

func doPreliminaryAPICall(endpointName string, u *url.URL, token string) {
}

func calculateStatus(count, totalLength int) {
}

func generateVerifyPage() {
}

func verifyPage(input []byte, verbose bool, doVerifyMerkleProof bool, token string) bool {
	panic("NotImplemented")
	return false
}

func verifyPageCLI(input []byte, verbose bool, doVerifyMerkleProof bool) bool {
	panic("NotImplemented")
	return false
}

/*
func makeSureAlwaysArray(x) {
}
*/

func transformMwXmlRevision2PkcJson(rev string) {
	panic("NotImplemented")
}

func transformRevisions(revisions []*revisionData) {
	panic("NotImplemented")
}

func parseMWXmlString(fileContent []byte) {
	panic("NotImplemented")
}
