package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
}

func (suite *TestSuite) SetupSuite() {
}

func (suite *TestSuite) TestOldVersionPath() {
	k8sServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer k8sServer.Close()

	ctx := context.Background()
	logger := logr.Discard()
	newKCClient, err := NewKeyCloakClient(k8sServer.URL, "test", "test", ctx, "test-realm", logger, "15.0.6")
	assert.Nil(suite.T(), err, "error was not nil")

	resp, err := newKCClient.rawMethod("GET", "/", "", map[string]string{})

	assert.Nil(suite.T(), err, "error was not nil")
	assert.Equal(suite.T(), resp.StatusCode, 200, "status code not good")
}

func (suite *TestSuite) TestNewVersionPath() {
	k8sServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer k8sServer.Close()

	ctx := context.Background()
	logger := logr.Discard()
	newKCClient, err := NewKeyCloakClient(k8sServer.URL, "test", "test", ctx, "test-realm", logger, "17.0.0")
	assert.Nil(suite.T(), err, "error was not nil")

	resp, err := newKCClient.rawMethod("GET", "/", "", map[string]string{})

	assert.Nil(suite.T(), err, "error was not nil")
	assert.Equal(suite.T(), resp.StatusCode, 200, "status code not good")
}

func (suite *TestSuite) TearDownSuite() {
}

func TestExampleTestSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
