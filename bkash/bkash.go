package bkash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	sandboxGateway       = "https://tokenized.sandbox.bka.sh/v1.2.0-beta"
	liveGateway          = "https://tokenized.pay.bka.sh"
	grantTokenUri        = "/tokenized/checkout/token/grant"
	refreshTokenUri      = "/tokenized/checkout/token/refresh"
	createAgreementUri   = "/tokenized/checkout/create"
	executeAgreementUri  = "/tokenized/checkout/execute"
	queryAgreementUri    = "/tokenized/checkout/agreement/status"
	cancelAgreementUri   = "/tokenized/checkout/agreement/cancel"
	createPaymentUri     = "/tokenized/checkout/create"
	executePaymentUri    = "/tokenized/checkout/execute"
	queryPaymentUri      = "/tokenized/checkout/payment/status"
	searchTransactionUri = "/tokenized/checkout/general/searchTransaction"
)

type Config struct {
	Username  string
	Password  string
	AppKey    string
	AppSecret string

	HttpClient *http.Client

	Logger *logrus.Logger

	IsLive bool
}

type Bkash struct {
	username  string
	password  string
	appKey    string
	appSecret string

	mu    sync.Mutex
	token *Token

	httpClient *http.Client

	logger *logrus.Logger

	isLive bool
}

func GetBkashTokenizedCheckoutService(conf *Config) (TokenizedCheckoutService, error) {
	client := conf.HttpClient
	if client == nil {
		client = &http.Client{
			Timeout: time.Second * 10,
		}
	}

	bkash := &Bkash{
		username:  conf.Username,
		password:  conf.Password,
		appKey:    conf.AppKey,
		appSecret: conf.AppSecret,

		token: nil,

		httpClient: client,

		logger: conf.Logger,

		isLive: conf.IsLive,
	}

	token, err := bkash.grantToken()
	if err != nil {
		return nil, err
	}

	bkash.token = token

	return bkash, nil
}

func (b *Bkash) CreateAgreement(request *CreateAgreementRequest) (*CreateAgreementResponse, error) {
	// Mode validation
	if request.Mode != "0000" {
		return nil, errors.New("invalid mode value")
	}

	createAgreementURL := b.getURL(createAgreementUri)

	r, err := b.newHttpRequestWithAuthorization("POST", createAgreementURL, request)

	resp := &createAgreementResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.CreateAgreementResponse, nil
}

func (b *Bkash) ExecuteAgreement(request *ExecuteAgreementRequest) (*ExecuteAgreementResponse, error) {
	executeAgreementURL := b.getURL(executeAgreementUri)

	r, err := b.newHttpRequestWithAuthorization("POST", executeAgreementURL, request)
	if err != nil {
		return nil, err
	}

	resp := &executeAgreementResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.ExecuteAgreementResponse, nil
}

func (b *Bkash) QueryAgreement(request *QueryAgreementRequest) (*QueryAgreementResponse, error) {
	queryAgreementURL := b.getURL(queryAgreementUri)

	r, err := b.newHttpRequestWithAuthorization("POST", queryAgreementURL, request)
	if err != nil {
		return nil, err
	}

	resp := &queryAgreementResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.QueryAgreementResponse, nil
}

func (b *Bkash) CancelAgreement(request *CancelAgreementRequest) (*CancelAgreementResponse, error) {
	cancelAgreementURL := b.getURL(cancelAgreementUri)

	r, err := b.newHttpRequestWithAuthorization("POST", cancelAgreementURL, request)
	if err != nil {
		return nil, err
	}

	resp := &cancelAgreementResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.CancelAgreementResponse, nil
}

func (b *Bkash) CreatePayment(request *CreatePaymentRequest) (*CreatePaymentResponse, error) {
	// Mode validation
	if request.Mode != "0001" {
		return nil, errors.New("invalid mode value")
	}

	createPaymentURL := b.getURL(createPaymentUri)

	r, err := b.newHttpRequestWithAuthorization("POST", createPaymentURL, request)
	if err != nil {
		return nil, err
	}

	resp := &createPaymentResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.CreatePaymentResponse, nil
}

func (b *Bkash) ExecutePayment(request *ExecutePaymentRequest) (*ExecutePaymentResponse, error) {
	executePayment := b.getURL(executePaymentUri)

	r, err := b.newHttpRequestWithAuthorization("POST", executePayment, request)
	if err != nil {
		return nil, err
	}

	resp := &executePaymentResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.ExecutePaymentResponse, nil
}

func (b *Bkash) QueryPayment(request *QueryPaymentRequest) (*QueryPaymentResponse, error) {
	queryPaymentURL := b.getURL(queryPaymentUri)

	r, err := b.newHttpRequestWithAuthorization("POST", queryPaymentURL, request)
	if err != nil {
		return nil, err
	}

	resp := &queryPaymentResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.QueryPaymentResponse, nil
}

func (b *Bkash) SearchTransaction(request *SearchTransactionRequest) (*SearchTransactionResponse, error) {
	searchTransactionURL := b.getURL(searchTransactionUri)

	r, err := b.newHttpRequestWithAuthorization("POST", searchTransactionURL, request)
	if err != nil {
		return nil, err
	}

	resp := &searchTransactionResponseJSON{}

	err = b.sendRequestToAPI(r, resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp.SearchTransactionResponse, nil
}

// grantToken gets Token
func (b *Bkash) grantToken() (*Token, error) {
	var data = make(map[string]string)

	data["app_key"] = b.appKey
	data["app_secret"] = b.appSecret

	grantTokenURL := b.getURL(grantTokenUri)

	r, err := newHttpRequest("POST", grantTokenURL, data)
	if err != nil {
		return nil, err
	}

	// set extra headers - those are outside the scope of newHttpRequest function
	r.Header.Add("username", b.username)
	r.Header.Add("password", b.password)

	tj := &tokenJSON{}

	err = b.sendRequestToAPI(r, tj)
	if err != nil {
		return nil, err
	}

	if tj.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    tj.StatusCode,
			StatusMessage: tj.StatusMessage,
		}
	}

	return &Token{
		TokenType:    tj.TokenType,
		ExpiresIn:    tj.expiry(),
		IdToken:      tj.IdToken,
		RefreshToken: tj.RefreshToken,
	}, nil
}

// refreshToken refreshes Bkash.token. It should be concurrency safe.
func (b *Bkash) refreshToken() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var data = make(map[string]string)

	data["app_key"] = b.appKey
	data["app_secret"] = b.appSecret
	data["refresh_token"] = b.token.RefreshToken

	refreshTokenURL := b.getURL(refreshTokenUri)

	r, err := newHttpRequest("POST", refreshTokenURL, data)
	if err != nil {
		return err
	}

	// set extra headers - those are outside the scope of newHttpRequest function
	r.Header.Add("username", b.username)
	r.Header.Add("password", b.password)

	tj := &tokenJSON{}

	err = b.sendRequestToAPI(r, tj)
	if err != nil {
		return err
	}

	if tj.StatusCode != "0000" {
		return gatewayError{
			StatusCode:    tj.StatusCode,
			StatusMessage: tj.StatusMessage,
		}
	}

	tkn := &Token{
		TokenType:    tj.TokenType,
		ExpiresIn:    tj.expiry(),
		IdToken:      tj.IdToken,
		RefreshToken: tj.RefreshToken,
	}
	b.token = tkn

	return nil
}

// getToken returns Bkash.token - it refreshes automatically if the token being expired.
// getToken should be concurrency safe.
func (b *Bkash) getToken() (*Token, error) {
	if !b.token.Valid() {
		if err := b.refreshToken(); err != nil {
			return nil, err
		}
	}

	return b.token, nil
}

// getURL takes path and returns a full URL string by concatenating path with gateway url.
// If Config.IsLive is true then liveGateway URL is being used, sandboxGateway URL is being used otherwise.
func (b *Bkash) getURL(path string) string {
	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += path

	return u.String()
}

// newHttpRequestWithAuthorization creates a http.Request with Authorization and X-App-key header & payload as Body.
//
// It calls getToken internally to obtain Authorization token.
func (b *Bkash) newHttpRequestWithAuthorization(method string, url string, payload interface{}) (*http.Request, error) {
	req, err := newHttpRequest(method, url, payload)
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	req.Header.Add("X-APP-Key", b.appKey)

	return req, nil
}

// sendRequestToAPI makes a request to the API, the response body will be unmarshalled into v.
// If timeout happens on client end ErrorTimeout returned as error. If http status code is not
// between 200 & 299 returns a HttpError.
//
// Other form of error can happen during ioutil.ReadAll or during json.Unmarshal function calls.
func (b *Bkash) sendRequestToAPI(req *http.Request, v interface{}) error {
	// Copy the request body before making the Do() call. This is because client.Do() will close the request.Body
	// and it's not possible to retrieve the body for further logging
	requestBodyBytes, _ := ioutil.ReadAll(req.Body)
	_ = req.Body.Close() // must close
	req.Body = ioutil.NopCloser(bytes.NewBuffer(requestBodyBytes))

	resp, err := b.httpClient.Do(req)
	b.log(req, requestBodyBytes, resp)

	if err != nil {
		if isClientTimeoutError(err) {
			return ErrorTimeout
		}
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		httpErr := &httpError{Response: resp}
		data, err := ioutil.ReadAll(resp.Body)

		if err == nil && len(data) > 0 {
			json.Unmarshal(data, httpErr)
		}

		return httpErr
	}

	return json.NewDecoder(resp.Body).Decode(v)
}

// log http.Request and http.Response if Config.Logger specified
func (b *Bkash) log(request *http.Request, requestBodyBytes []byte, response *http.Response) {
	if b.logger == nil {
		return
	}

	responseBodyBytes, _ := ioutil.ReadAll(response.Body)
	_ = response.Body.Close()
	response.Body = ioutil.NopCloser(bytes.NewBuffer(responseBodyBytes))

	var rsp = make(map[string]interface{})
	_ = json.Unmarshal(responseBodyBytes, &rsp)

	var rq = make(map[string]interface{})
	_ = json.Unmarshal(requestBodyBytes, &rq)

	fields := logrus.Fields{
		"url": request.URL.String(),
		"request_body": logrus.Fields{
			"method":      request.Method,
			"body_params": rq,
			"headers":     request.Header,
		},
		"api_response": rsp,
	}

	b.logger.WithFields(fields).Info()
}

// newHttpRequest creates a http.Request with payload as Body.
func newHttpRequest(method string, url string, payload interface{}) (*http.Request, error) {
	var buf io.Reader
	if payload != nil {
		p, err := json.Marshal(&payload)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewBuffer(p)
	}

	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")

	return req, nil
}
