package tests

import (
	"encoding/json"
	"github.com/sh0umik/bd-payment-gateway/bkash"
	"github.com/sh0umik/bd-payment-gateway/bkash/models"
	"testing"
)

func TestMessageSignatureValidation(t *testing.T) {
	notificationJson := `{"Type":"SubscriptionConfirmation","MessageId":"165545c9-2a5c-472c-8df2-7ff2be2b3b1b","Token":"2336412f37fb687f5d51e6e241d09c805a5a57b30d712f794cc5f6a988666d92768dd60a747ba6f3beb71854e285d6ad02428b09ceece29417f1f02d609c582afbacc99c583a916b9981dd2728f4ae6fdb82efd087cc3b7849e05798d2d2785c03b0879594eeac82c01f235d0e717736","TopicArn":"arn:aws:sns:us-west-2:123456789012:MyTopic","Message":"You have chosen to subscribe to the topic arn:aws:sns:us-west-2:123456789012:MyTopic.\nTo confirm the subscription, visit the SubscribeURL included in this message.","SubscribeURL":"https://sns.us-west-2.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-west-2:123456789012:MyTopic&Token=2336412f37fb687f5d51e6e241d09c805a5a57b30d712f794cc5f6a988666d92768dd60a747ba6f3beb71854e285d6ad02428b09ceece29417f1f02d609c582afbacc99c583a916b9981dd2728f4ae6fdb82efd087cc3b7849e05798d2d2785c03b0879594eeac82c01f235d0e717736","Timestamp":"2012-04-26T20:45:04.751Z","SignatureVersion":"1","Signature":"EXAMPLEpH+DcEwjAPg8O9mY8dReBSwksfg2S7WKQcikcNKWLQjwu6A4VbeS0QHVCkhRS7fUQvi2egU3N858fiTDN6bkkOxYDVrY0Ad8L10Hs3zH81mtnPk5uvvolIC1CXGu43obcgFxeL3khZl8IKvO61GWB6jI9b5+gLPoBc1Q=","SigningCertURL":"https://sns.us-west-2.amazonaws.com/SimpleNotificationService-f3ecfb7224c7233fe7bb5f59f96de52f.pem"}`
	var notificationPayload models.WebhookData

	err := json.Unmarshal([]byte(notificationJson), &notificationPayload)
	if err != nil {
		t.Fatal(err)
	}

	verifyErr := bkash.IsMessageSignatureValid(&notificationPayload)
	if verifyErr != nil {
		t.Fatal(verifyErr)
	}
	t.Log("valid payload")
}
