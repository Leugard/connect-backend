package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Leugard/connect-backend/service/auth"
	"github.com/Leugard/connect-backend/utils"
)

type contextKey string

const UserIDKey contextKey = "userID"

func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" || !strings.HasPrefix(token, "Bearer ") {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("missing or invalid authorization header"))
			return
		}

		token = strings.TrimPrefix(token, "Bearer ")

		userID, err := auth.ValidateJWT(token)
		if err != nil {
			utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid or expired tokken"))
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
