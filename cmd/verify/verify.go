// license ..

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/inblockio/aqua-verifier-go/api"
	"golang.org/x/crypto/sha3"
)

var (
	verbose   = flag.Bool("v", false, "Verbose")
	endpoint  = flag.String("server", "http://localhost:9352", "<The url of the server, e.g. https://pkc.inblock.io>")
	verify    = flag.Bool("ignore-merkle-proof", false, "Ignore verifying the witness merkle proof of each revision")
	authToken = flag.String("token", "", "(Optional) OAuth2 access token to access the API")
	dataFile  = flag.String("file", "", "(If present) The file to read from for the data")
	depth     = flag.Int("depth", -1, "(Optional) Depth to follow verification chain. By default, verifies all revisions")
	ap        *api.AquaProtocol
)

const (
	apiVersion      = "0.3.0"
	WARN            = "⚠️"
	CROSSMARK       = "❌"
	CHECKMARK       = "✅"
	LOCKED_WITH_PEN = "🔏"
	WATCH           = "⌚"
	BRANCH          = "🌿"
	FILE_GLYPH      = "📄"
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
		title := flag.Args()[0]
		if verifyPage(title) {
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

	for _, r := range data.Pages {
		verifyOfflineData(r, *verbose, *verify)
	}
	return true
}

func verifyPage(page string) bool {
	var err error
	ap, err = api.NewAPI(*endpoint, *authToken)
	if err != nil {
		fmt.Println(err)
		return false
	}
	s, err := ap.GetServerInfo()
	if err != nil {
		fmt.Println("Unable to query server info:", err)
		return false
	} else if s.ApiVersion != apiVersion {
		fmt.Println("Incompatible API version:")
		fmt.Println("Current supported version: ", apiVersion)
		fmt.Println("Server version: ", s.ApiVersion)
		return false
	}

	ri, err := ap.GetHashChainInfo("title", validateTitle(page))
	if err != nil {
		fmt.Println(err)
		return false
	}

	h, err := ap.GetRevisionHashes(ri.GenesisHash)
	if err != nil {
		fmt.Println(err)
		return false
	}

	if len(h) == 0 {
		// no data
		fmt.Println("No revision hashes found")
		return false
	}

	// starting at the latest revision, work backwards towards genesis hash
	cur := ri.LatestVerificationHash
	var height int
	if *depth == -1 || *depth > len(h) {
		height = len(h)
	} else if *depth < len(h) {
		height = *depth
	}

	// follow the revisions height deep, and order revisions from newest to oldest:
	verificationSet := make([]*api.Revision, height)
	for i := 0; i < height; i++ {
		r, err := ap.GetRevision(cur)
		if err != nil {
			fmt.Printf("Failure getting revision %s: %s\n", cur, err)
			return false
		}
		verificationSet[i] = r
		cur = r.Metadata.PreviousVerificationHash
	}

	fmt.Println("Verifying", height, "Revisions for", page)
	// verify each revision from oldest to newest
	for i := 0; i < len(verificationSet)-1; i += 1 {
		// this is the last (or only) element in the set to verify
		if i == len(verificationSet) {
			if !verifyRevision(verificationSet[i], nil) {
				return false
			}
		} else if !verifyRevision(verificationSet[i], verificationSet[i+1]) {
			return false
		}
	}
	return true
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

func calculateWitnessHash(domain_snapshot_genesis_hash, merkle_root, witness_network, witness_tx_hash string) string {
	return getHashSum(domain_snapshot_genesis_hash + merkle_root + witness_network + witness_tx_hash)
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

func checkEtherScan(r *api.Revision) bool {
	err := api.CheckEtherscan(r.Witness.WitnessNetwork, r.Witness.WitnessEventTransactionHash, r.Witness.WitnessEventVerificationHash)
	if err == nil {
		return true
	}
	return false
}

func printRevisionInfo(revision *api.Revision) {
}

func checkmarkCrossmark(isCorrect bool) string {
	if isCorrect {
		return CHECKMARK
	}
	return CROSSMARK
}

func verifyContent(content *api.RevisionContent) bool {
	actualHash := getHashSum(content.Content.Main + content.Content.SignatureSlot + content.Content.TransclusionHashes)
	return content.ContentHash == actualHash
}

func formatRevisionInfo2HTML(server *api.ServerInfo, detail *api.Revision, verbose bool) {
}

func formatPageInfo2HTML(serverUrl string, title string, status int, details string, verbose bool) {
}

func verifyRevisionMetadata(r *api.Revision) bool {
	mh := calculateMetadataHash(r.Metadata.DomainId,
		r.Metadata.Timestamp.String(),
		r.Metadata.PreviousVerificationHash)
	return mh == r.Metadata.MetadataHash
}

func verifyPreviousSignature(r *api.Revision, prev *api.Revision) error {
	// calculate and check prevSignatureHash from previous revision
	if !r.Context.HasPreviousSignature {
		return nil
	}
	if prev == nil {
		return errors.New("Revision has previous signature, but no previous revision provided to validate")
	}
	prevSignature := prev.Signature.Signature
	prevPublicKey := prev.Signature.PublicKey
	prevSignatureHash := calculateSignatureHash(prevSignature, prevPublicKey)
	if prevSignatureHash != prev.Signature.SignatureHash {
		return errors.New("Previous signature hash doesn't match")
	}
	return nil
}

func verifyWitness(r *api.Revision, prev *api.Revision) error {
	if r.Witness == nil {
		fmt.Printf("    %s Not witnessed\n", WARN)
		return nil
	}

	// calculate and check prevWitnessHash from previous revision
	if r.Context.HasPreviousWitness {
		if prev.Witness == nil {
			return errors.New("Previous witness data not found")
		}
		prevWitnessHash := calculateWitnessHash(
			prev.Witness.DomainSnapshotGenesisHash,
			prev.Witness.MerkleRoot,
			prev.Witness.WitnessNetwork,
			prev.Witness.WitnessEventTransactionHash)
		if prevWitnessHash != prev.Witness.WitnessHash {
			return errors.New("Witness hash doesn't match")
		}
	}
	if !checkEtherScan(r) {
		return errors.New("Error checking from etherscan.io")
	}
	return nil
}

func verifyVerificationHash(r *api.Revision, prev *api.Revision) error {
	// calculate verification hash
	prevSignatureHash := ""
	prevWitnessHash := ""
	if prev != nil {
		if prev.Signature != nil {
			prevSignatureHash = prev.Signature.SignatureHash
		}
		if prev.Witness != nil {
			prevWitnessHash = prev.Witness.WitnessHash
		}
	}
	verificationHash := calculateVerificationHash(r.Content.ContentHash, r.Metadata.MetadataHash, prevSignatureHash, prevWitnessHash)
	if verificationHash != r.Metadata.VerificationHash {
		if *verbose {
			fmt.Println("  Actual content hash: ", r.Content.ContentHash)
			fmt.Println("  Actual metadata hash: ", r.Metadata.MetadataHash)
			fmt.Println("  Actual signature hash: ", prevSignatureHash)
			if r.Witness != nil {
				fmt.Println("  Witness event id: ", r.Witness.WitnessEventId)
			}
			if r.Context.HasPreviousSignature {
				fmt.Println("  HasPreviousSignature")
			}
			if r.Context.HasPreviousWitness {
				fmt.Println("  HasPreviousWitness")
				fmt.Println("  Actual previous witness hash: ", prevWitnessHash)
			}
			fmt.Println("  Expected verification hash: ", r.Metadata.VerificationHash)
			fmt.Println("  Actual verification hash: ", verificationHash)
		}
		return errors.New("Verification hash doesn't match")
	}
	return nil
}

func jsonprint(f interface{}) {
	j, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Fatalf(err.Error())
	}
	fmt.Printf("%s\n", j)
}

func success(r *api.Revision) {
	fmt.Printf("  %s Verified\n", CHECKMARK)
	if *verbose {
		jsonprint(r.Metadata)
		jsonprint(r.Witness)
		jsonprint(r.Signature)
	}
}

func failure(r *api.Revision, context string) {
	log.Println("Failed to verify: ", context)
	if *verbose {
		jsonprint(r.Metadata)
		jsonprint(r.Witness)
		jsonprint(r.Signature)
	}
}

func verifyRevision(r *api.Revision, prev *api.Revision) bool {
	if !verifyRevisionMetadata(r) {
		failure(r, "Metadata hash doesn't match")
		return false
	}

	if !verifyContent(r.Content) {
		failure(r, "Content")
		return false
	}

	err := verifyPreviousSignature(r, prev)
	if err != nil {
		failure(r, "Signature")
		fmt.Println(err)
		return false
	}

	err = verifyWitness(r, prev)
	if err != nil {
		failure(r, "Witness")
		return false
	}

	// fmt.Printf("    %s%s Valid signature from wallet: %s\n", CHECKMARK, LOCKED_WITH_PEN, prev.Signature.WalletAddress)
	err = verifyVerificationHash(r, prev)
	if err != nil {
		failure(r, "Verification Hash")
		return false
	}

	success(r)
	return true
}

func calculateStatus(count, totalLength int) {
}

// verifyOfflineData verifies all revisions of a page.
func verifyOfflineData(data *api.OfflineRevisionInfo, verbose bool, doVerifyMerkleProof bool) bool {
	var height int
	if *depth == -1 || *depth > len(data.Revisions) {
		height = len(data.Revisions)
	} else if *depth < len(data.Revisions) {
		height = *depth
	}

	// follow the revisions height deep, and order revisions by oldest to newest:
	verificationSet := make([]*api.Revision, height)
	cur := data.LatestVerificationHash

	for i := 0; i < height; i++ {
		r, ok := data.Revisions[cur]
		if !ok {
			fmt.Printf("Failure getting revision %s\n", cur)
			return false
		}
		verificationSet[height-i-1] = r
		cur = r.Metadata.PreviousVerificationHash
	}

	fmt.Println("Verifying", height, "Revisions for", data.Title)
	// verify each revision from oldest to newest
	for i := 0; i < len(verificationSet); i++ {
		revision := verificationSet[i]
		fmt.Printf("%d. Verification of %s\n", i+1, revision.Metadata.VerificationHash)
		// this is the first (or only) element in the set to verify
		if i == 0 {
			if !verifyRevision(revision, nil) {
				return false
			}
		} else if !verifyRevision(revision, verificationSet[i-1]) {
			return false
		}
	}
	return true
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
