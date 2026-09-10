package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTokenStore implements the TokenStore interface for testing
type MockTokenStore struct {
	clients map[string]*types.ClientInfo
	grants  map[string]*types.Grant
	codes   map[string][2]string // code -> {grantID, userID}
	tokens  []*types.TokenData
}

func NewMockTokenStore() *MockTokenStore {
	return &MockTokenStore{
		clients: make(map[string]*types.ClientInfo),
		grants:  make(map[string]*types.Grant),
		codes:   make(map[string][2]string),
	}
}

func (m *MockTokenStore) GetClient(clientID string) (*types.ClientInfo, error) {
	if client, exists := m.clients[clientID]; exists {
		return client, nil
	}
	return nil, assert.AnError
}

func (m *MockTokenStore) StoreToken(token *types.TokenData) error {
	m.tokens = append(m.tokens, token)
	return nil
}

func (m *MockTokenStore) ValidateAuthCode(code string) (string, string, error) {
	if ids, exists := m.codes[code]; exists {
		return ids[0], ids[1], nil
	}
	return "", "", assert.AnError
}

func (m *MockTokenStore) GetGrant(grantID string, userID string) (*types.Grant, error) {
	if grant, exists := m.grants[grantID+":"+userID]; exists {
		return grant, nil
	}
	return nil, assert.AnError
}

func (m *MockTokenStore) DeleteAuthCode(code string) error {
	delete(m.codes, code)
	return nil
}

func (m *MockTokenStore) GetTokenByRefreshToken(refreshToken string) (*types.TokenData, error) {
	return nil, assert.AnError
}

func (m *MockTokenStore) RevokeToken(token string) error {
	return nil
}

// addPKCEGrant registers a public client and an authorization code grant. When
// codeChallenge is empty the grant did not use PKCE.
func (m *MockTokenStore) addPKCEGrant(code, grantID, userID, codeChallenge, codeChallengeMethod string) {
	m.clients["public-client"] = &types.ClientInfo{
		ClientID:                "public-client",
		TokenEndpointAuthMethod: "none",
		RedirectUris:            []string{"http://127.0.0.1:19876/mcp/oauth/callback"},
	}
	m.codes[code] = [2]string{grantID, userID}
	m.grants[grantID+":"+userID] = &types.Grant{
		ID:                  grantID,
		ClientID:            "public-client",
		UserID:              userID,
		Scope:               types.StringSlice{"openid"},
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
}

func pkceChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func postTokenForm(t *testing.T, handler http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestAuthorizationCodeGrantPKCE(t *testing.T) {
	const verifier = "test-code-verifier-with-sufficient-entropy-1234567890"

	t.Run("PKCEWithoutVerifierRejected", func(t *testing.T) {
		store := NewMockTokenStore()
		store.addPKCEGrant("code-1", "grant-1", "user-1", pkceChallenge(verifier), "S256")

		w := postTokenForm(t, NewHandler(store), url.Values{
			"grant_type": {"authorization_code"},
			"client_id":  {"public-client"},
			"code":       {"code-1"},
		})
		require.Equal(t, http.StatusBadRequest, w.Code)

		var errResp types.OAuthError
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Equal(t, "invalid_request", errResp.Error)
		assert.Contains(t, errResp.ErrorDescription, "code_verifier is required")
	})

	t.Run("PKCEWithValidVerifierAccepted", func(t *testing.T) {
		store := NewMockTokenStore()
		store.addPKCEGrant("code-2", "grant-2", "user-2", pkceChallenge(verifier), "S256")

		w := postTokenForm(t, NewHandler(store), url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"public-client"},
			"code":          {"code-2"},
			"code_verifier": {verifier},
		})
		require.Equal(t, http.StatusOK, w.Code)

		var resp types.TokenResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})

	t.Run("PKCEWithWrongVerifierRejected", func(t *testing.T) {
		store := NewMockTokenStore()
		store.addPKCEGrant("code-3", "grant-3", "user-3", pkceChallenge(verifier), "S256")

		w := postTokenForm(t, NewHandler(store), url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"public-client"},
			"code":          {"code-3"},
			"code_verifier": {"wrong-verifier-with-sufficient-entropy-000000000"},
		})
		require.Equal(t, http.StatusBadRequest, w.Code)

		var errResp types.OAuthError
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Equal(t, "invalid_grant", errResp.Error)
	})

	t.Run("VerifierRejectedForNonPKCEGrant", func(t *testing.T) {
		store := NewMockTokenStore()
		store.addPKCEGrant("code-4", "grant-4", "user-4", "", "")

		w := postTokenForm(t, NewHandler(store), url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"public-client"},
			"code":          {"code-4"},
			"redirect_uri":  {"http://127.0.0.1:19876/mcp/oauth/callback"},
			"code_verifier": {verifier},
		})
		require.Equal(t, http.StatusBadRequest, w.Code)

		var errResp types.OAuthError
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Equal(t, "invalid_request", errResp.Error)
		assert.Contains(t, errResp.ErrorDescription, "did not use PKCE")
	})

	t.Run("NonPKCEGrantWithRedirectURIAccepted", func(t *testing.T) {
		store := NewMockTokenStore()
		store.addPKCEGrant("code-5", "grant-5", "user-5", "", "")

		w := postTokenForm(t, NewHandler(store), url.Values{
			"grant_type":   {"authorization_code"},
			"client_id":    {"public-client"},
			"code":         {"code-5"},
			"redirect_uri": {"http://127.0.0.1:19876/mcp/oauth/callback"},
		})
		require.Equal(t, http.StatusOK, w.Code)

		var resp types.TokenResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.AccessToken)
	})
}
