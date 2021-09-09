package bkash

import (
	"net/http"
)

// TokenizedCheckoutService provides tokenized checkout payment service for bkash
type TokenizedCheckoutService interface {
	// CreateAgreement Initiates an agreement request for a customer.
	CreateAgreement(request *CreateAgreementRequest) (*CreateAgreementResponse, error)

	// CreateAgreementValidationListener is a handler func that receives paymentID & status
	// as a json post request and returns CreateAgreementValidationResponse object
	//
	// Deprecated: CreateAgreementValidationListener id deprecated, and should not be used.
	// Future release will drop the func.
	CreateAgreementValidationListener(r *http.Request) (*CreateAgreementValidationResponse, error)

	// ExecuteAgreement executes the agreement using the paymentID received from CreateAgreementValidationResponse
	ExecuteAgreement(request *ExecuteAgreementRequest) (*ExecuteAgreementResponse, error)

	// QueryAgreement query agreement by agreementID
	QueryAgreement(request *QueryAgreementRequest) (*QueryAgreementResponse, error)

	// CancelAgreement cancels an agreement by agreementID
	CancelAgreement(request *CancelAgreementRequest) (*CancelAgreementResponse, error)

	// CreatePayment Initiates a payment request for a customer.
	// Mode value should be "0001".
	CreatePayment(request *CreatePaymentRequest) (*CreatePaymentResponse, error)

	// ExecutePayment executes the agreement using the paymentID received from CreateAgreementValidationResponse
	ExecutePayment(request *ExecutePaymentRequest) (*ExecutePaymentResponse, error)

	// QueryPayment query payment by paymentID
	QueryPayment(request *QueryPaymentRequest) (*QueryPaymentResponse, error)
}
