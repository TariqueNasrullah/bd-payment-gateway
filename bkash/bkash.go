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

var EmptyRequiredField = errors.New("empty required field")

type Bkash struct {
	Username  string
	Password  string
	AppKey    string
	AppSecret string
}

func GetBkash(username, password, appKey, appSecret string) *Bkash {
	return &Bkash{
		Username:  username,
		Password:  password,
		AppKey:    appKey,
		AppSecret: appSecret,
	}
}

func (b *Bkash) GrantToken(isLiveStore bool) (*Token, error) {
	// Mandatory field validation
	if b.AppKey == "" || b.AppSecret == "" || b.Username == "" || b.Password == "" {
		return nil, EmptyRequiredField
	}

	var data = make(map[string]string)

	data["app_key"] = b.AppKey
	data["app_secret"] = b.AppSecret

	var storeUrl string
	if isLiveStore {
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
	r.Header.Add("username", b.Username)
	r.Header.Add("password", b.Password)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp Token
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (b *Bkash) RefreshToken(token *Token, isLiveStore bool) (*Token, error) {
	// Mandatory field validation
	if b.AppKey == "" || b.AppSecret == "" || token.RefreshToken == "" || b.Username == "" || b.Password == "" {
		return nil, EmptyRequiredField
	}

	var data = make(map[string]string)

	data["app_key"] = b.AppKey
	data["app_secret"] = b.AppSecret
	data["refresh_token"] = token.RefreshToken

	var storeUrl string
	if isLiveStore {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += refreshTokenUri

	refreshTokenURL := u.String()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	r, err := http.NewRequest("POST", refreshTokenURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("username", b.Username)
	r.Header.Add("password", b.Password)

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var resp Token
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (b *Bkash) CreateAgreement(request *CreateAgreementRequest, token *Token, isLiveStore bool) (*CreateAgreementResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.Mode == "" || request.CallbackUrl == "" {
		return nil, EmptyRequiredField
	}

	// Mode validation
	if request.Mode != "0000" {
		return nil, errors.New("invalid mode value")
	}

	var storeUrl string
	if isLiveStore {
		storeUrl = liveGateway
	} else {
		storeUrl = sandboxGateway
	}
	u, _ := url.ParseRequestURI(storeUrl)
	u.Path += createAgreementUri
	//u.RawQuery = data.Encode()

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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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

	return &resp, nil
}

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

func (b *Bkash) ExecuteAgreement(request *ExecuteAgreementRequest, token *Token, isLiveStore bool) (*ExecuteAgreementResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.PaymentID == "" {
		return nil, EmptyRequiredField
	}

	var storeUrl string
	if isLiveStore {
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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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

	return &resp, nil
}

func (b *Bkash) QueryAgreement(request *QueryAgreementRequest, token *Token, isLiveStore bool) (*QueryAgreementResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.AgreementID == "" {
		return nil, EmptyRequiredField
	}

	var storeUrl string
	if isLiveStore {
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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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

	return &resp, nil
}

func (b *Bkash) CancelAgreement(request *CancelAgreementRequest, token *Token, isLiveStore bool) (*CancelAgreementResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.AgreementID == "" {
		return nil, EmptyRequiredField
	}

	var storeUrl string
	if isLiveStore {
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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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

	return &resp, nil
}

func (b *Bkash) CreatePayment(request *CreatePaymentRequest, token *Token, isLiveStore bool) (*CreatePaymentResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.Mode == "" || request.CallbackURL == "" {
		return nil, EmptyRequiredField
	}

	// Mode validation
	if request.Mode != "0001" {
		return nil, errors.New("invalid mode value")
	}

	var storeUrl string
	if isLiveStore {
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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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

	return &resp, nil
}

func (b *Bkash) ExecutePayment(request *ExecutePaymentRequest, token *Token, isLiveStore bool) (*ExecutePaymentResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.PaymentID == "" {
		return nil, EmptyRequiredField
	}

	var storeUrl string
	if isLiveStore {
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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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

	return &resp, nil
}

func (b *Bkash) QueryPayment(request *QueryPaymentRequest, token *Token, isLiveStore bool) (*QueryPaymentResponse, error) {
	// Mandatory field validation
	if b.AppKey == "" || token.IdToken == "" || request.PaymentID == "" {
		return nil, EmptyRequiredField
	}

	var storeUrl string
	if isLiveStore {
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

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Content-Length", strconv.Itoa(len(jsonData)))
	r.Header.Add("Authorization", fmt.Sprintf("%s %s", token.TokenType, token.IdToken))
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
