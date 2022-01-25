package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

type KeyCloakClient struct {
	BaseURL     string
	Username    string
	Password    string
	AccessToken string
	Ctx         context.Context
	Log         logr.Logger
}

func NewKeyCloakClient(BaseUrl string, Username string, Password string, BaseCtx context.Context, Log logr.Logger) (*KeyCloakClient, error) {
	log := Log.WithValues("subsystem", "KeyCloakClient")
	client := KeyCloakClient{
		BaseURL:  BaseUrl,
		Username: Username,
		Password: Password,
		Ctx:      BaseCtx,
		Log:      log,
	}
	err := client.init()
	if err != nil {
		return nil, err
	}
	return &client, nil
}

type AuthStruct struct {
	AccessToken string `json:"access_token"`
}

func (k *KeyCloakClient) init() error {

	headers := map[string]string{
		"Content-type": "application/x-www-form-urlencoded",
	}

	resp, err := k.rawMethod(
		"POST",
		"/auth/realms/master/protocol/openid-connect/token",
		fmt.Sprintf(
			"grant_type=password&client_id=admin-cli&username=%s&password=%s",
			k.Username,
			k.Password,
		),
		headers,
	)
	if err != nil {
		return err
	}

	respObj := &AuthStruct{}

	data, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	json.Unmarshal(data, respObj)

	k.AccessToken = respObj.AccessToken

	return nil
}

func (k *KeyCloakClient) rawMethod(method string, url string, body string, headers map[string]string) (*http.Response, error) {
	fullUrl := fmt.Sprintf("%s%s", k.BaseURL, url)

	ctx, cancel := context.WithTimeout(k.Ctx, 10*time.Second)
	defer cancel()

	r := strings.NewReader(body)

	req, err := http.NewRequestWithContext(ctx, method, fullUrl, r)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}

	k.Log.Info(fmt.Sprintf("%s - %s - %d", url, method, resp.StatusCode))

	return resp, nil
}

func (k *KeyCloakClient) Get(url string, body string, headers map[string]string) (*http.Response, error) {
	headers["Authorization"] = fmt.Sprintf("Bearer %s", k.AccessToken)
	return k.rawMethod("GET", url, body, headers)
}

func (k *KeyCloakClient) Post(url string, body string, headers map[string]string) (*http.Response, error) {
	headers["Authorization"] = fmt.Sprintf("Bearer %s", k.AccessToken)

	return k.rawMethod("POST", url, body, headers)
}

func (k *KeyCloakClient) Put(url string, body string, headers map[string]string) (*http.Response, error) {
	headers["Authorization"] = fmt.Sprintf("Bearer %s", k.AccessToken)

	return k.rawMethod("PUT", url, body, headers)
}

type Realm struct {
	Realm string `json:"realm"`
}

type RealmResponse []Realm

func (k *KeyCloakClient) doesRealmExist(requestedRealmName string) (bool, error) {
	resp, err := k.Get("/auth/admin/realms", "", make(map[string]string))

	if err != nil {
		return false, err
	}

	iface := &RealmResponse{}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	err = json.Unmarshal(data, iface)

	if err != nil {
		return false, err
	}

	for _, realm := range *iface {
		if realm.Realm == requestedRealmName {
			return true, nil
		}
	}
	return false, nil
}

type Client struct {
	ClientId string `json:"clientId"`
}

type ClientResponse []Client

func (k *KeyCloakClient) doesClientExist(realm string, requestedClientName string) (bool, error) {
	resp, err := k.Get(fmt.Sprintf("/auth/admin/realms/%s/clients", realm), "", make(map[string]string))

	if err != nil {
		return false, err
	}

	iface := &ClientResponse{}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	err = json.Unmarshal(data, iface)

	if err != nil {
		return false, err
	}

	for _, client := range *iface {
		if client.ClientId == requestedClientName {
			return true, nil
		}
	}
	return false, nil
}

type User struct {
	Username string `json:"username"`
}

type UserResponse []User

func (k *KeyCloakClient) doesUserExist(realm string, requestedUsername string) (bool, *updateUserStruct, error) {
	resp, err := k.Get(fmt.Sprintf("/auth/admin/realms/%s/users", realm), "", make(map[string]string))

	if err != nil {
		return false, nil, err
	}

	iface := &[]updateUserStruct{}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	err = json.Unmarshal(data, iface)

	if err != nil {
		return false, nil, err
	}

	for _, user := range *iface {
		if user.Username == requestedUsername {
			return true, &user, nil
		}
	}
	return false, nil, nil
}

type createUserStruct struct {
	Enabled     bool              `json:"enabled"`
	Username    string            `json:"username"`
	FirstName   string            `json:"firstName"`
	LastName    string            `json:"lastName"`
	Email       string            `json:"email"`
	Attributes  userAttributes    `json:"attributes"`
	Credentials []userCredentials `json:"credentials"`
}

type userAttributes struct {
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	AccountID       string `json:"account_id"`
	AccountNumber   string `json:"account_number"`
	OrdID           string `json:"org_id"`
	IsInternal      bool   `json:"is_internal"`
	IsOrgAdmin      bool   `json:"is_org_admin"`
	IsActive        bool   `json:"is_active"`
	Entitlements    string `json:"entitlements"`
	NewEntitlements string `json:"newEntitlements"`
}

type updateUserStruct struct {
	ID          string               `json:"id"`
	Enabled     bool                 `json:"enabled"`
	Username    string               `json:"username"`
	FirstName   string               `json:"firstName"`
	LastName    string               `json:"lastName"`
	Email       string               `json:"email"`
	Attributes  updateUserAttributes `json:"attributes"`
	Credentials []userCredentials    `json:"credentials"`
}

type updateUserAttributes struct {
	FirstName       []string `json:"first_name"`
	LastName        []string `json:"last_name"`
	AccountID       []string `json:"account_id"`
	AccountNumber   []string `json:"account_number"`
	OrdID           []string `json:"org_id"`
	IsInternal      []string `json:"is_internal"`
	IsOrgAdmin      []string `json:"is_org_admin"`
	IsActive        []string `json:"is_active"`
	Entitlements    []string `json:"entitlements"`
	NewEntitlements []string `json:"newEntitlements"`
}

type userCredentials struct {
	Temporary bool   `json:"temporary"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

type createRealmStruct struct {
	Realm   string `json:"realm"`
	Enabled bool   `json:"enabled"`
	ID      string `json:"id"`
}

func (k *KeyCloakClient) createRealm(requestedRealmName string) error {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	postObj := createRealmStruct{
		Realm:   requestedRealmName,
		Enabled: true,
		ID:      requestedRealmName,
	}

	b, err := json.Marshal(postObj)

	if err != nil {
		return err
	}

	resp, err := k.Post("/auth/admin/realms", string(b), headers)

	if err != nil {
		v, _ := ioutil.ReadAll(resp.Body)
		k.Log.Error(err, string(v))
		return err
	}

	return nil
}

type mapperConfig struct {
	UserInfoTokenClaim bool   `json:"userinfo.token.claim"`
	UserAttribute      string `json:"user.attribute"`
	IDTokenClaim       bool   `json:"id.token.claim"`
	AccessTokenClaim   bool   `json:"access.token.claim"`
	ClaimName          string `json:"claim.name"`
	JSONTypeLabel      string `json:"jsonType.label"`
	Multivalued        bool   `json:"multivalued"`
}

type mapperStruct struct {
	Name            string       `json:"name"`
	ID              string       `json:"id"`
	Protocol        string       `json:"protocol"`
	ProtocolMapper  string       `json:"protocolMapper"`
	ConsentRequired bool         `json:"consentRequired"`
	Config          mapperConfig `json:"config"`
}

func createMapper(attr string, mtype string, multi bool) mapperStruct {
	return mapperStruct{
		Name:            attr,
		ID:              attr,
		Protocol:        "openid-connect",
		ProtocolMapper:  "oidc-usermodel-attribute-mapper",
		ConsentRequired: false,
		Config: mapperConfig{
			UserInfoTokenClaim: true,
			UserAttribute:      attr,
			IDTokenClaim:       true,
			AccessTokenClaim:   true,
			ClaimName:          attr,
			JSONTypeLabel:      mtype,
			Multivalued:        multi,
		},
	}
}

type clientStruct struct {
	ClientId                  string         `json:"clientId"`
	Enabled                   bool           `json:"enabled"`
	BearerOnly                bool           `json:"bearerOnly"`
	PublicClient              bool           `json:"publicClient"`
	BaseURL                   string         `json:"baseUrl"`
	RedirectUris              []string       `json:"redirectUris"`
	WebOrigins                []string       `json:"webOrigins"`
	ProtocolMappers           []mapperStruct `json:"protocolMappers"`
	DirectAccessGrantsEnabled bool           `json:"directAccessGrantsEnabled"`
}

func (k *KeyCloakClient) createClient(realmName, clientName, envName string) error {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	postObj := clientStruct{
		ClientId:                  clientName,
		Enabled:                   true,
		BearerOnly:                false,
		PublicClient:              true,
		RedirectUris:              []string{"*"},
		WebOrigins:                []string{"*"},
		BaseURL:                   fmt.Sprintf("https://%s", envName),
		DirectAccessGrantsEnabled: true,
		ProtocolMappers: []mapperStruct{
			createMapper("account_number", "String", false),
			createMapper("account_id", "String", false),
			createMapper("org_id", "String", false),
			createMapper("username", "String", false),
			createMapper("email", "String", false),
			createMapper("first_name", "String", false),
			createMapper("last_name", "String", false),
			createMapper("is_org_admin", "boolean", false),
			createMapper("is_internal", "boolean", false),
			createMapper("is_active", "boolean", false),
			createMapper("entitlements", "String", false),
			createMapper("newEntitlements", "String", true),
		},
	}

	b, err := json.Marshal(postObj)

	if err != nil {
		return err
	}

	resp, err := k.Post(
		fmt.Sprintf("/auth/admin/realms/%s/clients", realmName),
		string(b), headers,
	)

	if err != nil {
		v, _ := ioutil.ReadAll(resp.Body)
		k.Log.Error(err, string(v))
		return err
	}

	return nil
}

func (k *KeyCloakClient) createUser(realmName string, user *createUserStruct) error {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	b, err := json.Marshal(user)

	if err != nil {
		return err
	}

	resp, err := k.Post(
		fmt.Sprintf("/auth/admin/realms/%s/users", realmName),
		string(b), headers,
	)

	if err != nil {
		v, _ := ioutil.ReadAll(resp.Body)
		k.Log.Error(err, string(v))
		return err
	}

	return nil
}

func (k *KeyCloakClient) putUser(realmName string, user *updateUserStruct) error {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	b, err := json.Marshal(user)

	if err != nil {
		return err
	}

	resp, err := k.Put(
		fmt.Sprintf("/auth/admin/realms/%s/users/%s", realmName, user.ID),
		string(b), headers,
	)

	if err != nil {
		v, _ := ioutil.ReadAll(resp.Body)
		k.Log.Error(err, string(v))
		return err
	}

	return nil
}
