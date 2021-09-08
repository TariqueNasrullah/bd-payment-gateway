package bkash

import (
	"net/http"
)

// TokenizedCheckoutService provides tokenized checkout payment service for bkash
type TokenizedCheckoutService interface {
	// GrantToken creates a access token using bkash credentials
	GrantToken(isLiveStore bool) (*Token, error)

	// RefreshToken refreshes the access token
	RefreshToken(token *Token, isLiveStore bool) (*Token, error)

	// CreateAgreement Initiates an agreement request for a customer.
	CreateAgreement(request *CreateAgreementRequest, token *Token, isLiveStore bool) (*CreateAgreementResponse, error)

	// CreateAgreementValidationListener is a handler func that receives paymentID & status
	// as a json post request and returns CreateAgreementValidationResponse object
	//
	// Deprecated: CreateAgreementValidationListener id deprecated, and should not be used.
	// Future release will drop the func.
	CreateAgreementValidationListener(r *http.Request) (*CreateAgreementValidationResponse, error)

	// ExecuteAgreement executes the agreement using the paymentID received from CreateAgreementValidationResponse
	ExecuteAgreement(request *ExecuteAgreementRequest, token *Token, isLiveStore bool) (*ExecuteAgreementResponse, error)

	// QueryAgreement query agreement by agreementID
	QueryAgreement(request *QueryAgreementRequest, token *Token, isLiveStore bool) (*QueryAgreementResponse, error)

	// CancelAgreement cancels an agreement by agreementID
	CancelAgreement(request *CancelAgreementRequest, token *Token, isLiveStore bool) (*CancelAgreementResponse, error)

	// CreatePayment Initiates a payment request for a customer.
	// Mode value should be "0001".
	CreatePayment(request *CreatePaymentRequest, token *Token, isLiveStore bool) (*CreatePaymentResponse, error)

	// ExecutePayment executes the agreement using the paymentID received from CreateAgreementValidationResponse
	ExecutePayment(request *ExecutePaymentRequest, token *Token, isLiveStore bool) (*ExecutePaymentResponse, error)

	// QueryPayment query payment by paymentID
	QueryPayment(request *QueryPaymentRequest, token *Token, isLiveStore bool) (*QueryPaymentResponse, error)
}
