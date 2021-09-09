package bkash

import (
	"testing"
)

func TestBkash(t *testing.T) {
	username := "sandboxTokenizedUser01"
	password := "sandboxTokenizedUser12345"
	appKey := "7epj60ddf7id0chhcm3vkejtab"
	appSecret := "18mvi27h9l38dtdv110rq5g603blk0fhh5hg46gfb27cp2rbs66f"

	t.Run("should_produce_no_error", func(t *testing.T) {
		_, err := GetBkash(username, password, appKey, appSecret, false)
		if err != nil {
			t.Fatal("Expected no error, got err: ", err)
		}
	})

	t.Run("should_produce_error", func(t *testing.T) {
		_, err := GetBkash(username, password, appKey, "", false)
		if err == nil {
			t.Fatal("Expected error, got no error")
		}

		if _, ok := err.(GatewayError); !ok {
			t.Fatalf("expected error to be of type GatewayError, got of type: %v", err)
		}
	})

	t.Run("should_refresh_token", func(t *testing.T) {
		bkash, err := GetBkash(username, password, appKey, appSecret, false)
		if err != nil {
			t.Fatal("Expected no error, got err: ", err)
		}

		if b, ok := bkash.(*Bkash); ok {
			err := b.refreshToken()
			if err != nil {
				t.Fatal("Expected no error, got err: ", err)
			}
		} else {
			t.Fatal("type assertion failed")
		}

		t.Run("should_get_token", func(t *testing.T) {
			bkash, err := GetBkash(username, password, appKey, appSecret, false)
			if err != nil {
				t.Fatal("Expected no error, got err: ", err)
			}

			if b, ok := bkash.(*Bkash); ok {
				tkn, err := b.getToken()
				if err != nil {
					t.Fatal("Expected no error, got err: ", err)
				}

				if tkn.TokenType == "" {
					t.Fatal("Expected string, got empty")
				}
			} else {
				t.Fatal("type assertion failed")
			}
		})
	})

}
