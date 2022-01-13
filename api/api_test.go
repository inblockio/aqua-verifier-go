package api

import (
	"github.com/stretchr/testify/require"
	"testing"
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
	require.NotEqual(r.Content.Content.Main, "")
	require.NotEqual(r.Content.Content.TransclusionHashes, "")
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
	require.NotNil(r.Witness)
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
