package bkash

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"sync"
)

const (
	sandboxGateway      = "https://tokenized.sandbox.bka.sh/v1.2.0-beta"
	liveGateway         = "https://tokenized.pay.bka.sh"
	grantTokenUri       = "/tokenized/checkout/token/grant"
	refreshTokenUri     = "/tokenized/checkout/token/refresh"
	createAgreementUri  = "/tokenized/checkout/create"
	executeAgreementUri = "/tokenized/checkout/execute"
	queryAgreementUri   = "/tokenized/checkout/agreement/status"
	cancelAgreementUri  = "/tokenized/checkout/agreement/cancel"
	createPaymentUri    = "/tokenized/checkout/create"
	executePaymentUri   = "/tokenized/checkout/execute"
	queryPaymentUri     = "/tokenized/checkout/payment/status"
)

type Bkash struct {
	Username  string
	Password  string
	AppKey    string
	AppSecret string

	mu    sync.Mutex
	token *Token

	isLive bool
}

func GetBkash(username, password, appKey, appSecret string, isLive bool) (TokenizedCheckoutService, error) {
	token, err := grantToken(username, password, appKey, appSecret, isLive)
	if err != nil {
		return nil, err
	}
	return &Bkash{
		Username:  username,
		Password:  password,
		AppKey:    appKey,
		AppSecret: appSecret,
		token:     token,
		isLive:    isLive,
	}, nil
}

func grantToken(username, password, appKey, appSecret string, isLive bool) (*Token, error) {
	var data = make(map[string]string)

	data["app_key"] = appKey
	data["app_secret"] = appSecret

	var storeUrl string
	if isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}

	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += grantTokenUri

	grantTokenURL := u.String()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", grantTokenURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("username", username)
	r.Header.Add("password", password)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var tj tokenJSON
	err = json.Unmarshal(body, &tj)
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

func (b *Bkash) getToken() (*Token, error) {
	if !b.token.Valid() {
		if err := b.refreshToken(); err != nil {
			return nil, err
		}
	}

	return b.token, nil
}

func (b *Bkash) refreshToken() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var data = make(map[string]string)

	data["app_key"] = b.AppKey
	data["app_secret"] = b.AppSecret
	data["refresh_token"] = b.token.RefreshToken

	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += refreshTokenUri

	refreshTokenURL := u.String()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", refreshTokenURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("username", b.Username)
	r.Header.Add("password", b.Password)

	response, err := client.Do(r)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	var tj tokenJSON
	err = json.Unmarshal(body, &tj)
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

func (b *Bkash) CreateAgreement(request *CreateAgreementRequest) (*CreateAgreementResponse, error) {
	// Mode validation
	if request.Mode != "0000" {
		return nil, errors.New("invalid mode value")
	}

	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += createAgreementUri

	createAgreementURL := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", createAgreementURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp CreateAgreementResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

// Deprecated: CreateAgreementValidationListener id deprecated, and should not be used.
// Future release will drop the func.
func (b *Bkash) CreateAgreementValidationListener(r *http.Request) (*CreateAgreementValidationResponse, error) {
	if r.Method != "POST" {
		return nil, errors.New("method not allowed")
	}

	var agreementTValidationResponse CreateAgreementValidationResponse

	err := json.NewDecoder(r.Body).Decode(&agreementTValidationResponse)
	if err != nil {
		return nil, err
	}

	return &agreementTValidationResponse, nil
}

func (b *Bkash) ExecuteAgreement(request *ExecuteAgreementRequest) (*ExecuteAgreementResponse, error) {
	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += executeAgreementUri
	//u.RawQuery = data.Encode()

	executeAgreementURL := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", executeAgreementURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp ExecuteAgreementResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

func (b *Bkash) QueryAgreement(request *QueryAgreementRequest) (*QueryAgreementResponse, error) {
	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += queryAgreementUri
	//u.RawQuery = data.Encode()

	queryAgreementURL := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", queryAgreementURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp QueryAgreementResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

func (b *Bkash) CancelAgreement(request *CancelAgreementRequest) (*CancelAgreementResponse, error) {
	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += cancelAgreementUri
	//u.RawQuery = data.Encode()

	cancelAgreementURL := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", cancelAgreementURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp CancelAgreementResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

func (b *Bkash) CreatePayment(request *CreatePaymentRequest) (*CreatePaymentResponse, error) {
	// Mode validation
	if request.Mode != "0001" {
		return nil, errors.New("invalid mode value")
	}

	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += createPaymentUri

	createPaymentURL := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", createPaymentURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp CreatePaymentResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

func (b *Bkash) ExecutePayment(request *ExecutePaymentRequest) (*ExecutePaymentResponse, error) {
	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += executePaymentUri

	executePayment := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", executePayment, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp ExecutePaymentResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

func (b *Bkash) QueryPayment(request *QueryPaymentRequest) (*QueryPaymentResponse, error) {
	var storeUrl string
	if b.isLive {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += queryPaymentUri
	//u.RawQuery = data.Encode()

	queryPaymentURL := u.String()

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", queryPaymentURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	tkn, err := b.getToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", tkn.TokenType, tkn.IdToken))
	r.Header.Add("X-APP-Key", b.AppKey)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp QueryPaymentResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != "0000" {
		return nil, gatewayError{
			StatusCode:    resp.StatusCode,
			StatusMessage: resp.StatusMessage,
		}
	}

	return &resp, nil
}

// getMessageBytesToSign returns a byte array containing a signature usable for signature verification
func getMessageBytesToSign(msg *BkashIPNPayload) []byte {
	var builtSignature bytes.Buffer
	signableKeys := []string{"Message", "MessageId", "Subject", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"}
	for _, key := range signableKeys {
		reflectedStruct := reflect.ValueOf(msg)
		field := reflect.Indirect(reflectedStruct).FieldByName(key)
		value := field.String()
		if field.IsValid() && value != "" {
			builtSignature.WriteString(key + "\n")
			builtSignature.WriteString(value + "\n")
		}
	}
	return builtSignature.Bytes()
}

// IsMessageSignatureValid validates bkash IPN message signature. Returns true, nil if ok,
// otherwise returns false, error
func IsMessageSignatureValid(msg *BkashIPNPayload) error {
	resp, err := http.Get(msg.SigningCertURL)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("unable to get certificate err: " + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	p, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return err
	}

	base64DecodedSignature, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return err
	}

	if err := cert.CheckSignature(x509.SHA1WithRSA, getMessageBytesToSign(msg), base64DecodedSignature); err != nil {
		return err
	}

	return nil
}
