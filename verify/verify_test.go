package verify

import (
	"testing"

	"github.com/inblockio/aqua-verifier-go/api"
	"github.com/stretchr/testify/require"
)

func getFixtureVerificationSet() ([]*api.Revision, error) {
	data, err := readExportFile("test_fixtures/5e5a1ec586_Main_Page.json")
	if err != nil {
		return nil, err
	}
	page := data.Pages[0]
	depth := -1
	verificationSet, _, err := getVerificationSet(page, depth)
	return verificationSet, err
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

	// Test when current signature is invalid
	verificationSetWrong, err := getFixtureVerificationSet()
	require.NoError(err)
	first := verificationSetWrong[0]
	first.Signature.Signature = "wrong"
	isCorrect, result := verifyRevision(first, nil, doVerifyMerkleProof)
	require.False(isCorrect)
	require.EqualError(result.Error, "Current signature doesn't match")
}
