package bkash

// Response models for TOKENIZED CHECKOUT

type status struct {
	StatusCode    string `json:"statusCode,omitempty"`
	StatusMessage string `json:"statusMessage,omitempty"`
}

type CreateAgreementResponse struct {
	PaymentID            string `json:"paymentID,omitempty"`
	BkashURL             string `json:"bkashURL,omitempty"`
	CallbackURL          string `json:"callbackURL,omitempty"`
	SuccessCallbackURL   string `json:"successCallbackURL,omitempty"`
	FailureCallbackURL   string `json:"failureCallbackURL,omitempty"`
	CancelledCallbackURL string `json:"cancelledCallbackURL,omitempty"`
}

type createAgreementResponseJSON struct {
	CreateAgreementResponse
	status
}

type ExecuteAgreementResponse struct {
	PaymentID            string `json:"paymentID,omitempty"`
	AgreementID          string `json:"agreementID,omitempty"`
	CustomerMsisdn       string `json:"customerMsisdn,omitempty"`
	PayerReference       string `json:"payerReference,omitempty"`
	AgreementExecuteTime string `json:"agreementExecuteTime,omitempty"`
	AgreementStatus      string `json:"agreementStatus,omitempty"`
}

type executeAgreementResponseJSON struct {
	ExecuteAgreementResponse
	status
}

type QueryAgreementResponse struct {
	PaymentID            string `json:"paymentID,omitempty"`
	AgreementID          string `json:"agreementID,omitempty"`
	PayerReference       string `json:"payerReference,omitempty"`
	CustomerMsisdn       string `json:"customerMsisdn,omitempty"`
	AgreementCreateTime  string `json:"agreementCreateTime,omitempty"`
	AgreementExecuteTime string `json:"agreementExecuteTime,omitempty"`
	AgreementVoidTime    string `json:"agreementVoidTime,omitempty"`
	AgreementStatus      string `json:"agreementStatus,omitempty"`
}

type queryAgreementResponseJSON struct {
	QueryAgreementResponse
	status
}

type CancelAgreementResponse struct {
	PaymentID         string `json:"paymentID,omitempty"`
	AgreementID       string `json:"agreementID,omitempty"`
	PayerReference    string `json:"payerReference,omitempty"`
	AgreementVoidTime string `json:"agreementVoidTime,omitempty"`
	AgreementStatus   string `json:"agreementStatus,omitempty"`
}

type cancelAgreementResponseJSON struct {
	CancelAgreementResponse
	status
}

type CreatePaymentResponse struct {
	PaymentID             string `json:"paymentID,omitempty"`
	AgreementID           string `json:"agreementID,omitempty"`
	PaymentCreateTime     string `json:"paymentCreateTime,omitempty"`
	TransactionStatus     string `json:"transactionStatus,omitempty"`
	Amount                string `json:"amount,omitempty"`
	Currency              string `json:"currency,omitempty"`
	Intent                string `json:"intent,omitempty"`
	MerchantInvoiceNumber string `json:"merchantInvoiceNumber,omitempty"`
	BkashURL              string `json:"bkashURL,omitempty"`
	CallbackURL           string `json:"callbackURL,omitempty"`
	SuccessCallbackURL    string `json:"successCallbackURL,omitempty"`
	FailureCallbackURL    string `json:"failureCallbackURL,omitempty"`
	CancelledCallbackURL  string `json:"cancelledCallbackURL,omitempty"`
}

type createPaymentResponseJSON struct {
	CreatePaymentResponse
	status
}

type ExecutePaymentResponse struct {
	PaymentID             string `json:"paymentID,omitempty"`
	AgreementID           string `json:"agreementID,omitempty"`
	CustomerMsisdn        string `json:"customerMsisdn,omitempty"`
	PayerReference        string `json:"payerReference,omitempty"`
	AgreementExecuteTime  string `json:"agreementExecuteTime,omitempty"`
	AgreementStatus       string `json:"agreementStatus,omitempty"`
	PaymentExecuteTime    string `json:"paymentExecuteTime,omitempty"`
	TrxID                 string `json:"trxID,omitempty"`
	TransactionStatus     string `json:"transaction_status,omitempty"`
	Amount                string `json:"amount,omitempty"`
	Currency              string `json:"currency,omitempty"`
	Intent                string `json:"intent,omitempty"`
	MerchantInvoiceNumber string `json:"merchantInvoiceNumber,omitempty"`
}

type executePaymentResponseJSON struct {
	ExecutePaymentResponse
	status
}

type QueryPaymentResponse struct {
	PaymentID              string `json:"paymentID,omitempty"`
	Mode                   string `json:"mode,omitempty"`
	PayerReference         string `json:"payerReference,omitempty"`
	PaymentCreateTime      string `json:"paymentCreateTime,omitempty"`
	PaymentExecuteTime     string `json:"paymentExecuteTime,omitempty"`
	TrxID                  string `json:"trxID,omitempty"`
	TransactionStatus      string `json:"transaction_status,omitempty"`
	Amount                 string `json:"amount,omitempty"`
	Currency               string `json:"currency,omitempty"`
	Intent                 string `json:"intent,omitempty"`
	MerchantInvoiceNumber  string `json:"merchantInvoiceNumber,omitempty"`
	UserVerificationStatus string `json:"userVerificationStatus,omitempty"`
}

type queryPaymentResponseJSON struct {
	QueryPaymentResponse
	status
}

type SearchTransactionResponse struct {
	Amount                string `json:"amount,omitempty"`
	CompletedTime         string `json:"completedTime,omitempty"`
	Currency              string `json:"currency,omitempty"`
	CustomerMsisdn        string `json:"customerMsisdn,omitempty"`
	InitiationTime        string `json:"initiationTime,omitempty"`
	OrganizationShortCode string `json:"organizationShortCode,omitempty"`
	TransactionReference  string `json:"transactionReference,omitempty"`
	TransactionStatus     string `json:"transactionStatus,omitempty"`
	TransactionType       string `json:"transactionType,omitempty"`
	TrxID                 string `json:"trxID,omitempty"`
}

type searchTransactionResponseJSON struct {
	SearchTransactionResponse
	status
}

type CreateAgreementValidationResponse struct {
	PaymentID string `json:"paymentID,omitempty"`
	Status    string `json:"status,omitempty"`
}

type RefundTransactionResponse struct {
	CompletedTime     string `json:"completedTime,omitempty"`
	TransactionStatus string `json:"transactionStatus,omitempty"`
	OriginalTrxID     string `json:"originalTrxID,omitempty"`
	RefundTrxID       string `json:"refundTrxID,omitempty"`
	Amount            string `json:"amount,omitempty"`
	Currency          string `json:"currency,omitempty"`
	Charge            string `json:"charge,omitempty"`
}

type RefundStatusResponse struct {
	RefundTransactionResponse
}
