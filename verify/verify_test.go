package verify

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/inblockio/aqua-verifier-go/api"
	"github.com/stretchr/testify/require"
)

var fixture = readExportFileAsString("test_fixtures/5e5a1ec586_Main_Page.json")

func readExportFileAsString(filename string) []byte {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}
	return content
}

func jsonDecodeFixture(fixture []byte) (*api.OfflineData, error) {
	data := &api.OfflineData{}
	err := json.Unmarshal(fixture, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getFixtureVerificationSet() ([]*api.Revision, error) {
	data, err := jsonDecodeFixture(fixture)
	if err != nil {
		return nil, err
	}
	page := data.Pages[0]
	depth := -1
	verificationSet, _, err := getVerificationSet(page, depth)
	return verificationSet, err
}

func get1st2ndFixtureVerStructure() (*api.Revision, *api.Revision, error) {
	// Return the first and second revision
	verificationSet, err := getFixtureVerificationSet()
	if err != nil {
		return nil, nil, err
	}
	first := verificationSet[0]
	second := verificationSet[1]
	return first, second, nil
}

func verifyFirstRevision(first *api.Revision, args ...bool) (bool, *RevisionVerificationResult) {
	doVerifyMerkleProof := false
	if len(args) > 0 {
		doVerifyMerkleProof = args[0]
	}
	isCorrect, result := verifyRevision(first, nil, doVerifyMerkleProof)
	return isCorrect, result
}

func expectErrorFirstRevision(require *require.Assertions, first *api.Revision, errMsg string) *RevisionVerificationResult {
	isCorrect, result := verifyFirstRevision(first)
	require.False(isCorrect)
	require.EqualError(result.Error, errMsg)
	return result
}

func TestVerifyRevision(t *testing.T) {
	require := require.New(t)

	verificationSet, err := getFixtureVerificationSet()
	require.NoError(err)
	doVerifyMerkleProof := true

	require.NoError(err)

	for i := 0; i < len(verificationSet); i++ {
		revision := verificationSet[i]
		var prev *api.Revision
		if i == 0 {
			prev = nil
		} else {
			prev = verificationSet[i-1]
		}

		isCorrect, _ := verifyRevision(revision, prev, doVerifyMerkleProof)
		require.True(isCorrect)
	}
}

// TODO file verification!

func TestInvalidContent(t *testing.T) {
	// When the content is tampered
	require := require.New(t)
	first, _, err := get1st2ndFixtureVerStructure()
	require.NoError(err)
	first.Content.Content["main"] = "wrong"
	expectErrorFirstRevision(require, first, "Content hash doesn't match")
}

func TestInvalidMetadata(t *testing.T) {
	// When the metadata is tampered
	require := require.New(t)
	first, _, err := get1st2ndFixtureVerStructure()
	require.NoError(err)
	first.Metadata.DomainId = "wrong"
	expectErrorFirstRevision(require, first, "Metadata hash doesn't match")
}

func TestInvalidPreviousSignature(t *testing.T) {
	// When previous signature is tampered
	require := require.New(t)
	doVerifyMerkleProof := false
	first, second, err := get1st2ndFixtureVerStructure()
	require.NoError(err)

	first.Signature.Signature = "wrong"
	isCorrect, result := verifyRevision(second, first, doVerifyMerkleProof)
	require.False(isCorrect)
	require.EqualError(result.Error, "Previous signature hash doesn't match")

	// A different error message for when the prev revision is nil
	isCorrect, result = verifyRevision(second, nil, doVerifyMerkleProof)
	require.False(isCorrect)
	require.EqualError(result.Error, "Revision has previous signature, but no previous revision provided to validate")
}

func TestInvalidPreviousWitness(t *testing.T) {
	// When previous witness is tampered
	require := require.New(t)
	doVerifyMerkleProof := false
	first, second, err := get1st2ndFixtureVerStructure()
	require.NoError(err)

	first.Witness.MerkleRoot = "wrong"
	isCorrect, result := verifyRevision(second, first, doVerifyMerkleProof)
	require.False(isCorrect)
	require.EqualError(result.Error, "Previous witness hash doesn't match")

	// When the prev revision is set to nil when it is not supposed to
	first.Witness = nil
	isCorrect, result = verifyRevision(second, first, doVerifyMerkleProof)
	require.False(isCorrect)
	require.EqualError(result.Error, "Previous witness data not found")
}

func TestInvalidCurrentWitness(t *testing.T) {
	// When current witness is tampered
	require := require.New(t)
	doVerifyMerkleProof := true
	first, _, err := get1st2ndFixtureVerStructure()
	require.NoError(err)

	oldMR := first.Witness.MerkleRoot
	first.Witness.MerkleRoot = "wrong"
	isCorrect, result := verifyRevision(first, nil, doVerifyMerkleProof)
	require.False(isCorrect)
	require.Equal(result.Status.Witness, "INVALID")
	// Reset the merkle root to the correct one again, to prepare for the next
	// test.
	first.Witness.MerkleRoot = oldMR

	// When the Merkle proof is tampered
	first.Witness.MerkleProof[0].LeftLeaf = "wrong"
	isCorrect, result = verifyRevision(first, nil, doVerifyMerkleProof)
	require.False(isCorrect)
	require.Equal(result.WitnessResult.MerkleProofStatus, "INVALID")
}

func TestInvalidCurrentSignature(t *testing.T) {
	// When current signature is tampered
	require := require.New(t)
	first, _, err := get1st2ndFixtureVerStructure()
	require.NoError(err)
	first.Signature.Signature = "wrong"
	isCorrect, result := verifyFirstRevision(first)
	require.False(isCorrect)
	require.Equal(result.Status.Signature, "INVALID")
}

func TestInvalidVerificationHash(t *testing.T) {
	// When the verification hash is tampered
	require := require.New(t)
	first, _, err := get1st2ndFixtureVerStructure()
	require.NoError(err)
	first.Metadata.VerificationHash = "wrong"
	isCorrect, result := verifyFirstRevision(first)
	require.False(isCorrect)
	require.Equal(result.Status.Verification, "INVALID")
}
