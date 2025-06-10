package auth

import (
	"context"
	"fmt"

	"google.golang.org/api/idtoken"
)

func VerifyGoogleIDToken(idToken string) (*idtoken.Payload, error) {
	payload, err := idtoken.Validate(context.Background(), idToken, "")
	if err != nil {
		return nil, fmt.Errorf("invalid google token: %v", err)
	}

	return payload, nil
}
