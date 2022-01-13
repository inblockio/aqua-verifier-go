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
	t.Logf("%v", revInfo)
}

func TestGetRevisionHashes(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	revHashes, e := a.GetRevisionHashes("")
	require.Error(e)
	for _, rev := range revHashes {
		t.Logf("%v", rev)
	}
}

func TestGetRevision(t *testing.T) {
	require := require.New(t)
	a, e := NewAPI(testServer, testToken)
	require.NoError(e)
	r, e := a.GetRevision("")
	t.Logf("%v", r)
	require.Error(e)
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
