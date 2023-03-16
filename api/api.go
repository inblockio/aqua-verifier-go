// api.go contains the definitions of the api endpoints and datatypes defined
// at https://github.com/inblockio/aqua-doc/blob/main/Aqua_Protocol.md

package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// API endpoint definitions
	endpoint_get_hash_chain_info = "/data_accounting/get_hash_chain_info/"
	endpoint_get_revision_hashes = "/data_accounting/get_revision_hashes/"
	endpoint_get_revision        = "/data_accounting/get_revision/"
	endpoint_get_server_info     = "/data_accounting/get_server_info"
	timestamp_layout             = "20060102150405"

	// etherscan endpoint regular expression and seperator for scraping output
	etherscanRegexp = `<span id='rawinput'.+?>(.+?)<\/span>`
	ethMethodId     = "0x9cef4ea1"
	Version         = "0.3.0"
)

var (
	// etherscan mappings for various ethereum nets
	WitnessNetworkMap = map[string]string{
		"mainnet": "https://etherscan.io/tx",
		"ropsten": "https://ropsten.etherscan.io/tx",
		"kovan":   "https://kovan.etherscan.io/tx",
		"rinkeby": "https://rinkeby.etherscan.io/tx",
		"goerli":  "https://goerli.etherscan.io/tx",
	}
	re = regexp.MustCompile(etherscanRegexp)
)

// AquaProtocol holds the endpoint specific parameters and authentication token for an API session
type AquaProtocol struct {
	apiClient   http.Client
	apiEndpoint string
	authToken   string
	server      string
}

// ServerInfo holds the api response to
type ServerInfo struct {
	ApiVersion string `json:"api_version"`
}

// Namespace holdes the namestace field of a SiteInfo
type Namespace struct {
	Case  bool   `json:"case"`
	Title string `json:"title"`
}

// SiteInfo holds the SiteInfo part of a HashChainInfo
type SiteInfo struct {
	SiteName   string             `json:"sitename"`
	DbName     string             `json:"dbname"`
	Base       string             `json:"base"`
	Generator  string             `json:"generator"`
	Case       string             `json:"case"`
	Namespaces map[int]*Namespace `json:"namespaces"`
}

// HashChainInfo holds the api response to endpoint_get_hash_chain_info
type HashChainInfo struct {
	GenesisHash            string    `json:"genesis_hash"`
	DomainId               string    `json:"domain_id"`
	Content                string    `json:"content"`
	LatestVerificationHash string    `json:"latest_verification_hash"`
	SiteInfo               *SiteInfo `json:"site_info"`
	Title                  string    `json:"title"`
	Namespace              int       `json:"namespace"`
	ChainHeight            int       `json:"chain_height"`
}

// HashChain is the same as HashChainInfo but has a map of Revision keyed by revision hash
type HashChain struct {
	HashChainInfo
	Revisions map[string]*Revision `json:"revisions"`
}

// VerificationContext holds the Context in a Revision
type VerificationContext struct {
	HasPreviousSignature bool `json:"has_previous_signature"`
	HasPreviousWitness   bool `json:"has_previous_witness"`
}

type FileContent struct {
	Data     string `json:"data"`
	Filename string `json:"filename"`
	Size     int    `json:"size"`
	Comment  string `json:"comment"`
}

// RevisionContent holds the content and hash in a Revision
// For Content, we use a map with dynamic keys instead of hardcoded keys for
// Content because we want to future-proof it, so that future changes to
// Content keys does not require a code change here.
type RevisionContent struct {
	RevId       int               `json:"rev_id"`
	Content     map[string]string `json:"content"`
	ContentHash string            `json:"content_hash"`
	File        *FileContent      `json:"file"`
}

// Timestamp holds a timestamp in ??? format
type Timestamp struct {
	time.Time
}

// UnmarshalJSON unmarshals the timestamp field into a time.Time
func (p *Timestamp) UnmarshalJSON(bytes []byte) error {
	// XXX: bug, api returns string representation of timestamp, not int
	// remove quotes and parse the timestamp using the reference time
	// corresponding to the api endpoint format
	// https://pkg.go.dev/time#pkg-constants
	t, err := time.Parse(timestamp_layout, strings.ReplaceAll(string(bytes), `"`, ""))
	if err != nil {
		return err
	}
	p.Time = t
	return nil
}

func (p *Timestamp) String() string {
	return p.Format(timestamp_layout)
}

// RevisionMetadata holds the api response to endpoint_get_revision_
type RevisionMetadata struct {
	DomainId                 string    `json:"domain_id"`
	Timestamp                Timestamp `json:"time_stamp"`
	PreviousVerificationHash string    `json:"previous_verification_hash"`
	MetadataHash             string    `json:"metadata_hash"`
	VerificationHash         string    `json:"verification_hash"`
}

// RevisionHash holds the response to endpoint_get_revision_hashes
type RevisionHash string

// TODO: add deserialize methods to convert the hexadecimal string representation to binary

// RevisionSignature holds the signature and identity in a Revision
type RevisionSignature struct {
	Signature     string `json:"signature"`
	PublicKey     string `json:"public_key"`
	WalletAddress string `json:"wallet_address"`
	SignatureHash string `json:"signature_hash"`
}

// MerkleNode holds the entries for the structured merkle proof
type MerkleNode struct {
	WitnessEventId int `json:"witness_event_id"`
	Depth     int `json:"depth"`
	LeftLeaf  string `json:"left_leaf"`
	RightLeaf string `json:"right_leaf"`
	Successor string `json:"successor"`
}

// RevisionWitness holds the Witness data in a Revision
type RevisionWitness struct {
	WitnessEventId               int        `json:"witness_event_id"`
	DomainId                     string        `json:"domain_id"`
	DomainSnapshotTitle          string        `json:"domain_snapshot_title"`
	WitnessHash                  string        `json:"witness_hash"`
	DomainSnapshotGenesisHash    string        `json:"domain_snapshot_genesis_hash"`
	MerkleRoot                   string        `json:"merkle_root"`
	WitnessEventVerificationHash string        `json:"witness_event_verification_hash"`
	WitnessNetwork               string        `json:"witness_network"`
	SmartContractAddress         string        `json:"smart_contract_address"`
	WitnessEventTransactionHash  string        `json:"witness_event_transaction_hash"`
	SenderAccountAddress         string        `json:"sender_account_address"`
	Source                       string        `json:"source"`
	MerkleProof                  []*MerkleNode `json:"structured_merkle_proof"`
}

// Revision holds the api response to endpoint_get_revision
type Revision struct {
	Context   *VerificationContext `json:"verification_context"`
	Content   *RevisionContent     `json:"content"`
	Metadata  *RevisionMetadata    `json:"metadata"`
	Signature *RevisionSignature   `json:"signature"`
	Witness   *RevisionWitness     `json:"witness"`
}

// OfflineData holds the deserialized json-encoded export from PKC
type OfflineData struct {
	Pages    []*HashChain
	SiteInfo *SiteInfo
}

// GetHashChainInfo returns you all context for the requested hash_chain.
func (a *AquaProtocol) GetHashChainInfo(id_type, id string) (*HashChainInfo, error) {
	if id_type != "genesis_hash" && id_type != "title" {
		return nil, errors.New("id_type must be genesis_hash or title")
	}
	u, err := a.GetApiURL(endpoint_get_hash_chain_info + id_type + "?identifier=" + url.QueryEscape(id))
	if err != nil {
		return nil, err
	}
	resp, err := a.fetch(u)
	if err != nil {
		return nil, err
	}

	d := json.NewDecoder(resp.Body)
	r := new(HashChainInfo)
	err = d.Decode(r)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return r, nil
}

// GetRevisionHashes returns the revision requested if it exists and or a list of
// any newer revision then the one requested.
func (a *AquaProtocol) GetRevisionHashes(verification_hash string) ([]*RevisionHash, error) {
	u, err := a.GetApiURL(endpoint_get_revision_hashes + verification_hash)
	if err != nil {
		return nil, err
	}

	resp, err := a.fetch(u)
	if err != nil {
		return nil, err
	}

	d := json.NewDecoder(resp.Body)
	r := make([]*RevisionHash, 0)
	err = d.Decode(&r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// fetch makes a request with the Authorization token initialized for this api
// session and returns an *http.Response or error
func (a *AquaProtocol) fetch(u *url.URL) (*http.Response, error) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer"+a.authToken)
	resp, err := a.apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, errors.New("Request Not 200 OK")
	}
	return resp, err
}

// GetRevision returns all data revision and revision verification data.
func (a *AquaProtocol) GetRevision(verification_hash string) (*Revision, error) {
	u, err := a.GetApiURL(endpoint_get_revision + verification_hash)
	if err != nil {
		return nil, err
	}
	resp, err := a.fetch(u)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(resp.Body)
	r := new(Revision)
	err = d.Decode(r)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// GetApiURL returns the api endpoint base URL given a server hostname
func (a *AquaProtocol) GetApiURL(path string) (*url.URL, error) {
	u, err := url.Parse(a.apiEndpoint + path)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetServerInfo returns a serverInfo from the endpoint endpoint_get_server_info
func (a *AquaProtocol) GetServerInfo() (*ServerInfo, error) {
	u, err := a.GetApiURL(endpoint_get_server_info)
	if err != nil {
		return nil, err
	}
	resp, err := a.fetch(u)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(resp.Body)
	s := new(ServerInfo)
	err = d.Decode(s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// CheckEtherscan scrapes etherscan.io to see if the expected eventHash exists for a given transaction.
func CheckEtherscan(network, txHash, eventHash string) error {
	n, ok := WitnessNetworkMap[network]
	if !ok {
		return errors.New("Invalid ethereum network specified")
	}
	u, err := url.Parse(n)
	if err != nil {
		return err
	}
	u.Path = u.Path + "/" + txHash
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	// do the verification
	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	// To avoid IP banning by etherscan.io
	time.Sleep(300 * time.Millisecond)

	// read response
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// scrape output
	match := re.FindStringSubmatch(string(buf))
	if match == nil || len(match) < 2 { // no grouping match
		return errors.New("No Match")
	}
	// the response is prefixed by methodId
	d := strings.Split(match[1], ethMethodId)
	if len(d) != 2 {
		return errors.New("No Match")
	} else {
		if strings.ToLower(d[1]) != strings.ToLower(eventHash) {
			return errors.New("eventHash Does NOT match")
		}
		return nil
	}
}

/*
func doPreliminaryAPICall(endpointName string, u *url.URL, token string) {
}
*/

// NewAPI returns an initialized AquaProtocol using the server and authentication token
func NewAPI(endpoint, token string) (*AquaProtocol, error) {
	_, e := url.Parse(endpoint)
	if e != nil {
		return nil, e
	}
	// TODO: validate that the token is the correct form/length/etc...
	return &AquaProtocol{apiEndpoint: endpoint, authToken: token}, nil
}
