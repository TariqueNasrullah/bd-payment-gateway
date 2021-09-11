package bkash

import (
	"errors"
	"fmt"
	"net/http"
)

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

type HttpError interface {
	error
	HttpResponse() *http.Response
	Details() string
}

type httpError struct {
	Response *http.Response `json:"-"`
	Message  string         `json:"message"`
}

func (e *httpError) Error() string {
	if e.Message != "" {
		return e.Message
	}

	return e.Response.Status
}

func (e *httpError) HttpResponse() *http.Response {
	return e.Response
}

func (e *httpError) Details() string {
	return fmt.Sprintf("%v %v: %d %s", e.Response.Request.Method, e.Response.Request.URL, e.Response.StatusCode, e.Message)
}

func isClientTimeoutError(err error) bool {
	type timeoutError interface {
		Timeout() bool
	}
	te, ok := err.(timeoutError)
	return ok && te.Timeout()
}

var ErrorTimeout = errors.New("request timeout")
