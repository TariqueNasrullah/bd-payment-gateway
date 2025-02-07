package sslcom

import (
	"github.com/sh0umik/bd-payment-gateway/sslcom/models"
	"net/http"
)

type PaymentService interface {

	// Create session
	CreateSession(value *models.RequestValue) (*models.SessionResponse, error)

	// Set up IPN Listener
	IPNListener(request *http.Request) (*models.IpnResponse, error)

	// Validate the IPN Response
	OrderValidation(valId string) (*models.IpnResponse, error)

	// 	Order Validation
	CheckValidation(request *models.OrderValidationRequest) (*models.OrderValidationResponse, error)

	// Transaction query by Transaction ID
	TransactionQueryByTID(request *models.TransactionQueryRequest) (*models.TransactionQueryResponseTID, error)

	//Transaction query by Session Key
	TransactionQueryBySID(request *models.TransactionQueryRequest) (*models.TransactionQueryResponseSID, error)
}
