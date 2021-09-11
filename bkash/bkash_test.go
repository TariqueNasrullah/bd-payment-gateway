package bkash

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"testing"
)

var (
	username  = "sandboxTokenizedUser01"
	password  = "sandboxTokenizedUser12345"
	appKey    = "7epj60ddf7id0chhcm3vkejtab"
	appSecret = "18mvi27h9l38dtdv110rq5g603blk0fhh5hg46gfb27cp2rbs66f"

	//username := os.Getenv("USERNAME")
	//password := os.Getenv("PASSWORD")
	//appKey := os.Getenv("APP_KEY")
	//appSecret := os.Getenv("APP_SECRET")
)

func TestBkash(t *testing.T) {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{PrettyPrint: true})

	bkash, err := GetBkashTokenizedCheckoutService(&Config{
		Username:   username,
		Password:   password,
		AppKey:     appKey,
		AppSecret:  appSecret,
		HttpClient: nil,
		Logger:     logger,
		IsLive:     false,
	})
	if err != nil {
		t.Fatal("Expected no error, got err: ", err)
	}

	t.Run("create_agreement", func(t *testing.T) {
		createAgreementResponse, err := bkash.CreateAgreement(&CreateAgreementRequest{
			Mode:                  "0000",
			PayerReference:        "01537161343",
			CallbackUrl:           "http://mydomain.com/bkash",
			Amount:                "",
			Currency:              "",
			Intent:                "",
			MerchantInvoiceNumber: "",
		})
		if err != nil {
			t.Fatal(err)
		}

		if createAgreementResponse.PaymentID == "" || createAgreementResponse.BkashURL == "" {
			t.Fatal("invalid create agreement response")
		}
	})

	t.Run("execute_agreement", func(t *testing.T) {
		executeAgreementResponse, err := bkash.ExecuteAgreement(&ExecuteAgreementRequest{PaymentID: "TR00007X1631515655460"})
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(executeAgreementResponse)
	})
}
