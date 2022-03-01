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

func getFirstFixtureVS() (*api.Revision, error) {
	verificationSet, err := getFixtureVerificationSet()
	if err != nil {
		return nil, err
	}
	first := verificationSet[0]
	return first, nil
}

func verifyFirstRevision(first *api.Revision, args ...bool) (bool, *RevisionVerificationResult) {
	doVerifyMerkleProof := true
	if len(args) > 0 {
		doVerifyMerkleProof = args[0]
	}
	isCorrect, result := verifyRevision(first, nil, doVerifyMerkleProof)
	return isCorrect, result
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
	first, err := getFirstFixtureVS()
	require.NoError(err)
	first.Content.Content["main"] = "wrong"
	isCorrect, result := verifyFirstRevision(first)
	require.False(isCorrect)
	require.EqualError(result.Error, "Content hash doesn't match")
}

func TestInvalidMetadata(t *testing.T) {
	// When the metadata is tampered
	require := require.New(t)
	first, err := getFirstFixtureVS()
	require.NoError(err)
	first.Metadata.DomainId = "wrong"
	isCorrect, result := verifyFirstRevision(first)
	require.False(isCorrect)
	require.EqualError(result.Error, "Metadata hash doesn't match")
}
func TestInvalidPreviousSignature(t *testing.T) {
	// When previous signature is tampered
	require := require.New(t)
	doVerifyMerkleProof := true
	verificationSet, err := getFixtureVerificationSet()
	require.NoError(err)
	first := verificationSet[0]
	second := verificationSet[1]
	first.Signature.Signature = "wrong"
	isCorrect, result := verifyRevision(second, first, doVerifyMerkleProof)
	require.False(isCorrect)
	require.EqualError(result.Error, "Previous signature hash doesn't match")
}

func TestInvalidCurrentSignature(t *testing.T) {
	// When current signature is tampered
	require := require.New(t)
	first, err := getFirstFixtureVS()
	require.NoError(err)
	first.Signature.Signature = "wrong"
	isCorrect, result := verifyFirstRevision(first)
	require.False(isCorrect)
	require.Equal(result.Status.Signature, "INVALID")
}
