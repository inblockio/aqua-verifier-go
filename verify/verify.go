package verify

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/inblockio/aqua-verifier-go/api"
	"golang.org/x/crypto/sha3"
)

const (
	WARN            = "⚠️"
	CROSSMARK       = "❌"
	CHECKMARK       = "✅"
	LOCKED_WITH_PEN = "🔏"
	WATCH           = "⌚"
	BRANCH          = "🌿"
	FILE_GLYPH      = "📄"
	space4          = "    "
	// Verification status
	INVALID_VERIFICATION_STATUS  = "INVALID"
	VERIFIED_VERIFICATION_STATUS = "VERIFIED"
	ERROR_VERIFICATION_STATUS    = "ERROR"
	// https://stackoverflow.com/questions/9781218/how-to-change-node-jss-console-font-color
	Reset    = "\x1b[0m"
	Dim      = "\x1b[2m"
	FgRed    = "\x1b[31m"
	FgYellow = "\x1b[33m"
	FgWhite  = "\x1b[37m"
	BgGreen  = "\x1b[42m"
)

var Verbose bool

type RevisionVerificationStatus struct {
	Content      bool
	Metadata     bool
	Signature    string
	Witness      string
	Verification string
	File         string
}

type RevisionVerificationResult struct {
	VerificationHash string
	Status           *RevisionVerificationStatus
	WitnessResult    *WitnessResult
	FileHash         string
	Error            error
	Elapsed          time.Duration
}

type WitnessResult struct {
	WitnessHash                        string
	TxHash                             string
	WitnessNetwork                     string
	EtherscanResult                    string
	EtherscanErrorMessage              string
	ActualWitnessEventVerificationHash string
	WitnessEventVHMatches              bool
	// `extra` is populated with useful info when the witness event verification
	// doesn't match.
	Extra               *WitnessResultExtra
	DoVerifyMerkleProof bool
	MerkleProofStatus   string
}

type WitnessResultExtra struct {
	DomainSnapshotGenesisHash    string
	MerkleRoot                   string
	WitnessEventVerificationHash string
}

func VerifyData(fileName string, ignoreMerkleProof bool, depth int) bool {
	data, err := readExportFile(fileName)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if Verbose {
		j, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Fatalf(err.Error())
		}
		fmt.Printf("Decoded input as:\n%s\n", j)
	}

	for _, r := range data.Pages {
		verifyOfflineData(r, !ignoreMerkleProof, depth)
	}
	return true
}

func VerifyPage(ap *api.AquaProtocol, page string, doVerifyMerkleProof bool, depth int) bool {
	var err error
	s, err := ap.GetServerInfo()
	if err != nil {
		fmt.Println("Unable to query server info:", err)
		return false
	} else if s.ApiVersion != api.Version {
		fmt.Println("Incompatible API version:")
		fmt.Println("Current supported version: ", api.Version)
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
	if depth == -1 || depth > len(h) {
		height = len(h)
	} else if depth < len(h) {
		height = depth
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
		var prev *api.Revision
		if i == len(verificationSet) {
			// this is the last (or only) element in the set to verify
			prev = nil
		} else {
			prev = verificationSet[i+1]
		}
		revision := verificationSet[i]
		isCorrect, result := verifyRevision(revision, prev, doVerifyMerkleProof)
		printRevisionInfo(result, revision)
		if !isCorrect {
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

func cliRedify(content string) string {
	return FgRed + content + Reset
}

func cliYellowfy(content string) string {
	return FgYellow + content + Reset
}

func logRed(content string) {
	fmt.Println(cliRedify(content))
}

func logYellow(content string) {
	fmt.Println(cliYellowfy(content))
}

func logDim(content string) {
	fmt.Println(Dim + content + Reset)
}

func formatDBTimestamp(ts time.Time) string {
	return ts.Format("Jan 2, 2006, 3:04:05 PM UTC")
}

func shortenHash(hash string) string {
	return hash[:6] + "..." + hash[len(hash)-6:]
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
	} else if s.ApiVersion == api.Version {
		return true
	}
	return false
}

func checkEtherScan(r *api.Revision) error {
	return api.CheckEtherscan(r.Witness.WitnessNetwork, r.Witness.WitnessEventTransactionHash, r.Witness.WitnessEventVerificationHash)
}

func printWitnessInfo(result *RevisionVerificationResult) {
	if result.Status.Witness == "MISSING" {
		logDim(space4 + WARN + " Not witnessed")
		return
	}

	space2 := "  "
	wr := result.WitnessResult
	wh := shortenHash(wr.WitnessHash)
	witOut := space2 + "Witness event " + wh + " detected"
	witOut += "\n" + space4 + "Transaction hash: " + wr.TxHash
	suffix := " on " + wr.WitnessNetwork + " via etherscan.io"
	if wr.EtherscanResult == "true" {
		witOut += "\n" + space4 + CHECKMARK + WATCH + "Witness event verification hash has been verified" + suffix
	} else if wr.EtherscanResult == "false" {
		witOut += cliRedify(
			"\n" + space4 + CROSSMARK + WATCH + "Witness event verification hash does not match" + suffix,
		)
	} else {
		witOut += cliRedify(
			"\n" + space4 + CROSSMARK + WATCH + wr.EtherscanErrorMessage + suffix,
		)
		witOut += cliRedify(
			"\n" + space4 + "Error code: " + wr.EtherscanResult,
		)
		witOut += cliRedify(
			"\n" + space4 + "Verify manually: " + wr.ActualWitnessEventVerificationHash,
		)
	}
	if !wr.WitnessEventVHMatches {
		witOut += cliRedify(
			"\n" + space4 + CROSSMARK +
				"Witness event verification hash doesn't match",
		)
		witOut += cliRedify(
			"\n" + space4 + "Domain Snapshot genesis hash: " + wr.Extra.DomainSnapshotGenesisHash,
		)
		witOut += cliRedify(
			"\n" + space4 + "Merkle root: " + wr.Extra.MerkleRoot,
		)
		witOut += cliRedify(
			"\n" + space4 + "Expected: " + wr.Extra.WitnessEventVerificationHash,
		)
		witOut += cliRedify(
			"\n" + space4 + "Actual: " + wr.ActualWitnessEventVerificationHash,
		)
	}

	if wr.DoVerifyMerkleProof && wr.MerkleProofStatus != "" {
		switch wr.MerkleProofStatus {
		case "DOMAIN_SNAPSHOT":
			witOut += "\n" + space4 + CHECKMARK + "Is a Domain Snapshot, hence not part of Merkle Proof"
		case "VALID":
			witOut += "\n" + space4 + CHECKMARK + BRANCH + "Witness Merkle Proof is OK"
		default:
			witOut += "\n" + space4 + CROSSMARK + BRANCH + "Witness Merkle Proof is corrupted"
		}
	}

	fmt.Println(witOut)
}

func printRevisionInfo(result *RevisionVerificationResult, r *api.Revision) {
	if result.Error != nil {
		logRed(result.Error.Error())
		return
	}

	fmt.Printf("  Elapsed: %.2f s\n", result.Elapsed.Seconds())
	fmt.Println("  Timestamp:", formatDBTimestamp(r.Metadata.Timestamp.Time))
	fmt.Println("  Domain ID:", r.Metadata.DomainId)
	if result.Status.Verification == INVALID_VERIFICATION_STATUS {
		logRed("  " + CROSSMARK + " Verification hash doesn't match")
		return
	}
	fmt.Printf("  %s Verification hash matches\n", CHECKMARK)

	if Verbose {
		fmt.Println("TODO")
	}

	printWitnessInfo(result)

	switch result.Status.Signature {
	case "VALID":
		fmt.Printf("    %s%s Valid signature from wallet: %s\n", CHECKMARK, LOCKED_WITH_PEN, r.Signature.WalletAddress)
	case "MISSING":
		logDim(space4 + WARN + " Not signed")
	case "INVALID":
		logRed("    " + CROSSMARK + LOCKED_WITH_PEN + "Invalid signature\n")
	}
}

func checkmarkCrossmark(isCorrect bool) string {
	if isCorrect {
		return CHECKMARK
	}
	return CROSSMARK
}

func getSortedKeys(m map[string]string) []string {
	keys := make([]string, len(m))
	i := 0
	for key := range m {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	return keys
}

func verifyContent(content *api.RevisionContent) bool {
	wholeContent := ""
	// We sort the keys by alphabetical order, just the way it is done for
	// canonical JSON.
	for _, key := range getSortedKeys(content.Content) {
		wholeContent += content.Content[key]
	}
	actualHash := getHashSum(wholeContent)
	return content.ContentHash == actualHash
}

func formatRevisionInfo2HTML(server *api.ServerInfo, detail *api.Revision) {
}

func formatPageInfo2HTML(serverUrl string, title string, status int, details string) {
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

func verifyPreviousWitness(r *api.Revision, prev *api.Revision) error {
	// calculate and check prevWitnessHash from previous revision
	if !r.Context.HasPreviousWitness {
		return nil
	}
	if prev.Witness == nil {
		return errors.New("Previous witness data not found")
	}
	prevWitnessHash := calculateWitnessHash(
		prev.Witness.DomainSnapshotGenesisHash,
		prev.Witness.MerkleRoot,
		prev.Witness.WitnessNetwork,
		prev.Witness.WitnessEventTransactionHash)
	if prevWitnessHash != prev.Witness.WitnessHash {
		return errors.New("Previous witness hash doesn't match")
	}
	return nil
}

func verifyMerkleIntegrity(merkleBranch []*api.MerkleNode, verificationHash string) bool {
	if len(merkleBranch) == 0 {
		return false
	}

	var prevSuccessor string
	for _, node := range merkleBranch {
		leaves := map[string]bool{
			node.LeftLeaf:  true,
			node.RightLeaf: true,
		}
		if prevSuccessor != "" {
			if !leaves[prevSuccessor] {
				//console.log("Expected leaf", prevSuccessor)
				//console.log("Actual leaves", leaves)
				return false
			}
		} else {
			// This means we are at the beginning of the loop.
			if !leaves[verificationHash] {
				// In the beginning, either the left or right leaf must match the
				// verification hash.
				return false
			}
		}

		var calculatedSuccessor string
		if node.LeftLeaf == "" {
			calculatedSuccessor = node.RightLeaf
		} else if node.RightLeaf == "" {
			calculatedSuccessor = node.LeftLeaf
		} else {
			calculatedSuccessor = getHashSum(node.LeftLeaf + node.RightLeaf)
		}
		if calculatedSuccessor != node.Successor {
			//console.log("Expected successor", calculatedSuccessor)
			//console.log("Actual successor", node.successor)
			return false
		}
		prevSuccessor = node.Successor
	}
	return true
}

func verifyWitness(r *api.Revision, doVerifyMerkleProof bool) (string, *WitnessResult) {
	if r.Witness == nil {
		return "MISSING", nil
	}

	actualWitnessEventVerificationHash := getHashSum(
		r.Witness.DomainSnapshotGenesisHash + r.Witness.MerkleRoot,
	)

	result := &WitnessResult{
		WitnessHash:                        r.Witness.WitnessHash,
		TxHash:                             r.Witness.WitnessEventTransactionHash,
		WitnessNetwork:                     r.Witness.WitnessNetwork,
		EtherscanResult:                    "",
		EtherscanErrorMessage:              "",
		ActualWitnessEventVerificationHash: actualWitnessEventVerificationHash,
		WitnessEventVHMatches:              true,
		// `extra` is populated with useful info when the witness event verification
		// doesn't match.
		Extra:               nil,
		DoVerifyMerkleProof: doVerifyMerkleProof,
		MerkleProofStatus:   "",
	}

	// Do online lookup of transaction hash
	etherScanResult := "true"
	if err := checkEtherScan(r); err != nil {
		etherScanResult = err.Error()
		var errMsg string
		if etherScanResult == "Transaction hash not found" {
			errMsg = "Transaction hash not found"
		} else if strings.Contains(etherScanResult, "ENETUNREACH") {
			errMsg = "Server is unreachable"
		} else {
			errMsg = "Online lookup failed"
		}
		result.EtherscanErrorMessage = errMsg
	}
	result.EtherscanResult = etherScanResult

	if actualWitnessEventVerificationHash != r.Witness.WitnessEventVerificationHash {
		result.WitnessEventVHMatches = false
		result.Extra = &WitnessResultExtra{
			DomainSnapshotGenesisHash:    r.Witness.DomainSnapshotGenesisHash,
			MerkleRoot:                   r.Witness.MerkleRoot,
			WitnessEventVerificationHash: r.Witness.WitnessEventVerificationHash,
		}
		return "INVALID", result
	}
	// At this point, we know that the witness matches.
	if doVerifyMerkleProof {
		// Only verify the witness merkle proof when verifyWitness is successful,
		// because this step is expensive.
		verificationHash := r.Metadata.VerificationHash
		if verificationHash == r.Witness.DomainSnapshotGenesisHash {
			// Corner case when the page is a Domain Snapshot.
			result.MerkleProofStatus = "DOMAIN_SNAPSHOT"
		} else {
			if merkleProofIsOK := verifyMerkleIntegrity(r.Witness.MerkleProof, verificationHash); merkleProofIsOK {
				result.MerkleProofStatus = "VALID"
			} else {
				result.MerkleProofStatus = "INVALID"
				return "INVALID", result
			}
		}
	}
	if etherScanResult != "true" {
		return "INVALID", result
	}
	return "VALID", result
}

func verifyCurrentSignature(r *api.Revision) (bool, string) {
	if r.Signature == nil || r.Signature.Signature == "" {
		return true, "MISSING"
	}
	verificationHash := r.Metadata.VerificationHash
	paddedMessage := []byte("I sign the following page verification_hash: [0x" + verificationHash + "]")
	signature, err := hexutil.Decode(r.Signature.Signature)
	if err != nil {
		return false, "INVALID"
	}
	signature[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	sigPublicKey, err := crypto.Ecrecover(accounts.TextHash(paddedMessage), signature)
	if err != nil {
		return false, "INVALID"
	}
	ecdsaPub, err := crypto.UnmarshalPubkey(sigPublicKey)
	if err != nil {
		return false, "INVALID"
	}
	sigAddress := crypto.PubkeyToAddress(*ecdsaPub).Hex()
	if strings.ToLower(sigAddress) != strings.ToLower(r.Signature.WalletAddress) {
		return false, "INVALID"
	}
	return true, "VALID"
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
		if Verbose {
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

func NewRevisionVerificationResult(verificationHash string) *RevisionVerificationResult {
	rvr := new(RevisionVerificationResult)
	// Populate with default values
	rvr.Status = new(RevisionVerificationStatus)
	rvr.Status.Signature = "MISSING"
	rvr.Status.Witness = "MISSING"
	rvr.Status.Verification = INVALID_VERIFICATION_STATUS
	rvr.Status.File = "MISSING"
	rvr.VerificationHash = verificationHash
	return rvr
}

func verifyRevisionWithoutElapsed(r *api.Revision, prev *api.Revision, doVerifyMerkleProof bool) (bool, *RevisionVerificationResult) {
	result := NewRevisionVerificationResult(r.Metadata.VerificationHash)

	if !verifyRevisionMetadata(r) {
		result.Error = errors.New("Metadata hash doesn't match")
		return false, result
	}
	// Mark metadata as correct
	result.Status.Metadata = true

	if !verifyContent(r.Content) {
		result.Error = errors.New("Content hash doesn't match")
		return false, result
	}
	// Mark content as correct
	result.Status.Content = true

	err := verifyPreviousSignature(r, prev)
	if err != nil {
		result.Error = err
		return false, result
	}

	err = verifyPreviousWitness(r, prev)
	if err != nil {
		result.Error = err
		return false, result
	}

	witnessStatus, witnessResult := verifyWitness(r, doVerifyMerkleProof)
	result.Status.Witness = witnessStatus
	result.WitnessResult = witnessResult
	witnessIsCorrect := witnessStatus != "INVALID"

	signatureIsCorrect, status := verifyCurrentSignature(r)
	result.Status.Signature = status

	err = verifyVerificationHash(r, prev)
	if err != nil {
		// TODO make this interface consistent with other error formatting.
		result.Status.Verification = INVALID_VERIFICATION_STATUS
		return false, result
	}
	result.Status.Verification = VERIFIED_VERIFICATION_STATUS

	return signatureIsCorrect && witnessIsCorrect, result
}

func verifyRevision(r *api.Revision, prev *api.Revision, doVerifyMerkleProof bool) (bool, *RevisionVerificationResult) {
	// Wrap verifyRevisionWithoutElapsed so that it contains elapsed info.
	elapsedStart := time.Now()
	isCorrect, result := verifyRevisionWithoutElapsed(r, prev, doVerifyMerkleProof)
	elapsed := time.Since(elapsedStart)
	result.Elapsed = elapsed
	return isCorrect, result
}

func calculateStatus(count, totalLength int) {
}

// verifyOfflineData verifies all revisions of a page.
func verifyOfflineData(data *api.OfflineRevisionInfo, doVerifyMerkleProof bool, depth int) bool {
	var height int
	if depth == -1 || depth > len(data.Revisions) {
		height = len(data.Revisions)
	} else if depth < len(data.Revisions) {
		height = depth
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
		var prev *api.Revision
		if i == 0 {
			// this is the first (or only) element in the set to verify
			prev = nil
		} else {
			prev = verificationSet[i-1]
		}
		isCorrect, result := verifyRevision(revision, prev, doVerifyMerkleProof)
		printRevisionInfo(result, revision)
		if !isCorrect {
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
