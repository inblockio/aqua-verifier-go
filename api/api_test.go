package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testServer = "http://localhost:9352/rest.php"
	testToken  = ""
)

func TestGetHashChainInfo(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	revInfo, e := a.GetHashChainInfo("title", "Main_Page")
	require.NoError(e)
	require.NotEqual(revInfo.GenesisHash, "")
	require.NotEqual(revInfo.LatestVerificationHash, "")
	require.NotEqual(revInfo.DomainId, "")
	require.NotNil(revInfo.SiteInfo)
	require.NotEqual(revInfo.SiteInfo.SiteName, "")
	require.NotEqual(revInfo.SiteInfo.DbName, "")
	require.NotEqual(revInfo.SiteInfo.Base, "")
	require.NotEqual(revInfo.SiteInfo.Generator, "")
	require.NotEqual(revInfo.SiteInfo.Case, "")
	require.NotNil(revInfo.SiteInfo.Namespaces)
	require.NotEmpty(revInfo.SiteInfo.Namespaces)
	t.Logf("Deserialized RevisionInfo: %v", revInfo)
}

func TestGetRevisionHashes(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	// get a verification hash from the main page
	revInfo, e := a.GetHashChainInfo("title", "Main_Page")
	require.NoError(e)
	require.NotEqual(revInfo.LatestVerificationHash, "")

	revHashes, e := a.GetRevisionHashes(revInfo.LatestVerificationHash)
	require.NoError(e)
	require.NotEmpty(revHashes)
	for _, rev := range revHashes {
		t.Logf("VerificationHash: %v", *rev)
	}
}

func TestGetRevision(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	// get a verification hash from the main page
	revInfo, e := a.GetHashChainInfo("title", "Main_Page")
	require.NoError(e)
	require.NotEqual(revInfo.LatestVerificationHash, "")

	r, e := a.GetRevision(revInfo.LatestVerificationHash)
	require.NoError(e)

	require.NotNil(r.Context)
	require.NotNil(r.Content)
	require.NotEqual(r.Content.ContentHash, "")
	require.NotNil(r.Content.Content)
	require.NotEqual(r.Content.Content["main"], "")
	require.NotEqual(r.Content.Content["transclusion-hashes"], "")
	require.NotNil(r.Metadata)
	require.NotEqual(r.Metadata.DomainId, "")
	require.NotEqual(r.Metadata.Timestamp, 0)
	//require.NotEqual(r.Metadata.PreviousVerificationHash, "")
	require.NotEqual(r.Metadata.MetadataHash, "")
	require.NotEqual(r.Metadata.VerificationHash, "")
	require.NotNil(r.Signature)
	// FIXME: these fields are optional and not present on the default installation Main_Page
	//require.NotEqual(r.Signature.Signature, "")
	//require.NotEqual(r.Signature.PublicKey, "")
	//require.NotEqual(r.Signature.WalletAddress, "")
	//require.NotEqual(r.Signature.SignatureHash, "")
	// FIXME: the default micro-pkc installation does not have any witness data
	//require.NotNil(r.Witness)
	//require.NotEqual(r.Witness.WitnessEventId, "")
	//require.NotEqual(r.Witness.DomainId, "")
	//require.NotEqual(r.Witness.DomainSnapshotTitle, "")
	//require.NotEqual(r.Witness.WitnessHash, "")
	//require.NotEqual(r.Witness.DomainSnapshotGenesisHash, "")
	//require.NotEqual(r.Witness.MerkleRoot, "")
	//require.NotEqual(r.Witness.WitnessEventVerificationHash, "")
	//require.NotEqual(r.Witness.WitnessNetwork, "")
	//require.NotEqual(r.Witness.SmartContractAddress, "")
	//require.NotEqual(r.Witness.WitnessEventTransactionHash, "")
	//require.NotEqual(r.Witness.SenderAccountAddress, "")
	//require.NotEqual(r.Witness.Source, "")
	//require.NotNil(r.Witness.MerkleProof)
	//for _, n := range r.Witness.MerkleProof {
	//	require.NotEqual(n.WitnessEventId, "")
	//	require.NotEqual(n.Depth, "")
	//	require.NotEqual(n.RightLeaf, "")
	//	require.NotEqual(n.LeftLeaf, "")
	//	require.NotEqual(n.Successor, "")
	//}
	t.Logf("%v", *r)
}

func TestGetApiURL(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	u, e := a.GetApiURL("")
	require.NoError(e)
	require.NotEqual(u.String(), "")
}

func TestGetServerInfo(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	info, e := a.GetServerInfo()
	require.NoError(e)
	t.Logf("%s", info)
}

func TestEtherscan(t *testing.T) {
	require := require.New(t)
	txHash := "0xc8c56a7aa002056d2f6fe2bf2c35fd7e4fd69bd41a81f4089bc28b8f015aa90b"
	eventHash := "55bbd044788cd625c40a1c4a31d42c17324926f295e10711f3c22c46d55683288e3c00e802cf242ec1a25f70eec545bd91e210a92e4f5354fe8d69f65044aa94"
	e := CheckEtherscan("goerli", txHash, eventHash)
	require.NoError(e)
}
