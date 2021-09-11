package bkash

type CreateAgreementRequest struct {
	Mode                  string `json:"mode,omitempty"`
	PayerReference        string `json:"payerReference,omitempty"`
	CallbackUrl           string `json:"callbackURL,omitempty"`
	Amount                string `json:"amount,omitempty"`
	Currency              string `json:"currency,omitempty"`
	Intent                string `json:"intent,omitempty"`
	MerchantInvoiceNumber string `json:"merchantInvoiceNumber,omitempty"`
}

type ExecuteAgreementRequest struct {
	PaymentID string `json:"paymentID,omitempty"`
}

type QueryAgreementRequest struct {
	AgreementID string `json:"agreementID,omitempty"`
}

type CancelAgreementRequest struct {
	AgreementID string `json:"agreementID,omitempty"`
}

type CreatePaymentRequest struct {
	Mode                    string `json:"mode,omitempty"`
	PayerReference          string `json:"payerReference,omitempty"`
	CallbackURL             string `json:"callbackURL,omitempty"`
	AgreementID             string `json:"agreementID,omitempty"`
	Amount                  string `json:"amount,omitempty"`
	Currency                string `json:"currency,omitempty"`
	Intent                  string `json:"intent,omitempty"`
	MerchantInvoiceNumber   string `json:"merchantInvoiceNumber,omitempty"`
	MerchantAssociationInfo string `json:"merchantAssociationInfo,omitempty"`
}

type ExecutePaymentRequest struct {
	PaymentID string `json:"paymentID,omitempty,"`
}

type QueryPaymentRequest struct {
	PaymentID string `json:"paymentID,omitempty"`
}

type SearchTransactionRequest struct {
	TrxID string `json:"trxID,omitempty"`
}

type RefundTransactionRequest struct {
	PaymentID string `json:"paymentID,omitempty"`
	Amount    string `json:"amount,omitempty"`
	TrxID     string `json:"trxID,omitempty"`
	Sku       string `json:"sku,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type RefundStatusRequest struct {
	PaymentID string `json:"paymentID,omitempty"`
	TrxID     string `json:"trxID,omitempty"`
}
