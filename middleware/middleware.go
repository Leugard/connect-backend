package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Leugard/connect-backend/service/auth"
	"github.com/Leugard/connect-backend/types"
	"github.com/Leugard/connect-backend/utils"
	"github.com/google/uuid"
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

func RequireVerified(getUserByID func(uuid.UUID) (*types.User, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userIDRaw := r.Context().Value(UserIDKey)
			if userIDRaw == nil {
				utils.WriteError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
				return
			}

			userID, ok := userIDRaw.(string)
			if !ok {
				utils.WriteError(w, http.StatusForbidden, fmt.Errorf("invalid user ID"))
				return
			}

			id, _ := uuid.Parse(userID)
			user, err := getUserByID(id)
			if err != nil || !user.IsVerified {
				utils.WriteError(w, http.StatusForbidden, fmt.Errorf("account not verified"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
