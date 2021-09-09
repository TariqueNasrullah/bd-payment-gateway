package bkash

type GatewayError interface {
	error
	ErrorCode() string
}

type gatewayError struct {
	StatusCode    string `json:"statusCode,omitempty"`
	StatusMessage string `json:"statusMessage,omitempty"`
}

func (e gatewayError) Error() string {
	return e.StatusMessage
}

func (e gatewayError) ErrorCode() string {
	return e.StatusCode
}
