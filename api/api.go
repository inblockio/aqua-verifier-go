// api.go contains the definitions of the api endpoints and datatypes defined
// at https://github.com/inblockio/aqua-doc/blob/main/Aqua_Protocol.md

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	// API endpoint definitions
	endpoint_api                 = "/rest.php/"
	endpoint_get_hash_chain_info = endpoint_api + "/data_accounting/get_hash_chain_info/"
	endpoint_get_revision_hashes = endpoint_api + "/data_accounting/get_revision_hashes/"
	endpoint_get_revision        = endpoint_api + "/data_accounting/get_revision/"
	endpoint_get_server_info     = endpoint_api + "/data_accounting/get_server_info"
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

// SiteInfo holds the SiteInfo part of a RevisionInfo
type SiteInfo struct {
	SiteName   string             `json:"sitename"`
	DbName     string             `json:"dbname"`
	Base       *url.URL           `json:"base"`
	Generator  string             `json:"generator"`
	Case       bool               `json:"case"`
	Namespaces map[int]*Namespace `json:"namespace"`
}

// RevisionInfo holds the api response to endpoint_get_revision_hashes
type RevisionInfo struct {
	GenesisHash            string    `json:"genesis_hash"`
	CurrentRevision        string    `json:"current_revision"`
	DomainId               string    `json:"domain_id"`
	Content                string    `json:"content"`
	LatestVerificationHash string    `json:"latest_verification_hash string"`
	SiteInfo               *SiteInfo `json:"site_info"`
	Title                  string    `json:"title"`
	Namespace              int       `json:"namespace"`
	ChainHeight            int       `json:"chain_height"`
}

// VerificationContext holds the Context in a Revision
// XXX: what is a Context exactly?
type VerificationContext struct {
}

// RevisionContent holds the content and hash in a Revision
type RevisionContent struct {
	ContentData string `json:"content_data"`
	ContentHash string `json:"content_hash"`
}

// RevisionMetadata holds the api response to endpoint_get_revision_
type RevisionMetadata struct {
	domain_id                  string    `json:"domain_id"`
	timestamp                  time.Time `json:"timestamp"`
	previous_verification_hash string    `json:"previous_verification_hash"`
}

// RevisionSignature holds the signature and identity in a Revision
type RevisionSignature struct {
	Signature     string `json:"signature"`
	WalletAddress string `json:"wallet_address"`
	SignatureHash string `json:"signature_hash"`
}

// RevisionWitness holds the Witness data in a Revision
type RevisionWitness struct {
	DomainManifestGenesisHash string `json:"domain_manifest_genesis_hash s"`
	MerkleRoot                string `json:"merkle_root"`
	WitnessNetwork            string `json:"witness_network"`
	Transaction               string `json:"transaction"`
	WitnessHash               string `json:"witness_hash"`
}

// XXX: RevisionMerkleTreeProof holds the ??? in a Revision
type RevisionMerkleTreeProof struct {
}

// Revision holds the api response to endpoint_get_revision
type Revision struct {
	Context         *VerificationContext     `json:"context"`
	Content         *RevisionContent         `json:"content"`
	Metadata        *RevisionMetadata        `json:"metadata"`
	Signature       *RevisionSignature       `json:"signature"`
	Witness         *RevisionWitness         `json:"witness"`
	MerkleTreeProof *RevisionMerkleTreeProof `json:"merkle_tree_proof"`
}

// GetHashChainInfo returns you all context for the requested hash_chain.
func (a *AquaProtocol) GetHashChainInfo(id_type, id string) (*RevisionInfo, error) {
	if id_type != "genesis_hash" || id_type != "title" {
		return nil, errors.New("id_type must be genesis_hash or title")
	}
	u, err := url.Parse(endpoint_get_hash_chain_info + id_type + "/" + id)
	if err != nil {
		return nil, err
	}
	resp, err := a.fetch(u)
	if err != nil {
		return nil, err
	}

	d := json.NewDecoder(resp.Body)
	r := new(RevisionInfo)
	err = d.Decode(r)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return r, nil
}

// GetRevisionHashes returns the revision requested if it exists and or a list of
// any newer revision then the one requested.
func (a *AquaProtocol) GetRevisionHashes(verification_hash string) ([]*Revision, error) {
	u, err := url.Parse(endpoint_get_revision_hashes + verification_hash)
	if err != nil {
		return nil, err
	}
	// XXX: do the api call

	resp, err := a.fetch(u)
	if err != nil {
		return nil, err
	}

	// XXX: unclear if this will deserialize a response that is a single element into a list of 1
	// otherwise need to handle both cases.
	d := json.NewDecoder(resp.Body)
	r := make([]*Revision, 0)
	err = d.Decode(r)
	if err != nil {
		log.Println(err)
		panic(err)
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
	return a.apiClient.Do(req)
}

// GetRevisionHashes
// XXX: incomplete copypasta of the js impl.
//func GetRevisionHashes(apiURL *url.URL, title string, token string) *RevisionInfo {
//	u, err := url.Parse(apiURL.String() + "/" + "get_hash_chain_info/title" + title)
//	if err != nil {
//		log.Println(err)
//		return nil
//	}
//	resp, err := FetchWithToken(u, token)
//	if err != nil {
//		log.Println(err)
//		return nil
//	}
//	d := json.NewDecoder(resp.Body)
//	h := new(hashChainInfo)
//	err = d.Decode(h)
//	if err != nil {
//		log.Println(err)
//		return nil
//	}
//	return h
//}

// GetRevision returns all data revision and revision verification data.
func (a *AquaProtocol) GetRevision(verification_hash string) (*Revision, error) {
	u, err := url.Parse(endpoint_get_revision + verification_hash)
	if err != nil {
		return nil, err
	}
	resp, err := a.fetch(u)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	d := json.NewDecoder(resp.Body)
	r := new(Revision)
	err = d.Decode(r)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return r, nil
}

// GetApiURL returns the api endpoint base URL given a server hostname
func (a *AquaProtocol) GetApiURL() *url.URL {
	u, err := url.Parse(a.server + a.apiEndpoint)
	if err != nil {
		panic(err)
	}
	return u
}

// GetServerInfo returns a serverInfo from the endpoint endpoint_get_server_info
func (a *AquaProtocol) GetServerInfo(server string) *ServerInfo {
	u, err := url.Parse(endpoint_get_server_info)
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
	s := new(ServerInfo)
	err = d.Decode(s)
	if err != nil {
		log.Println(err)
		return nil
	}
	return s
}

/*
func doPreliminaryAPICall(endpointName string, u *url.URL, token string) {
}
*/

// NewAPI returns an initialized AquaProtocol using the server and authentication token
func NewAPI(server, token string) (*AquaProtocol, error) {
	// TODO: parse server and confirm it is a valid hostname or return error
	// TODO: validate that the token is the correct form/length/etc...
	return &AquaProtocol{server: server, authToken: token, apiEndpoint: endpoint_api}, nil
}
