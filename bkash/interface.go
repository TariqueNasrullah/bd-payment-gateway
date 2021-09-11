package bkash

// TokenizedCheckoutService provides tokenized checkout payment service for bkash
type TokenizedCheckoutService interface {
	// CreateAgreement Initiates an agreement request for a customer.
	CreateAgreement(request *CreateAgreementRequest) (*CreateAgreementResponse, error)

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

	SearchTransaction(request *SearchTransactionRequest) (*SearchTransactionResponse, error)
}
