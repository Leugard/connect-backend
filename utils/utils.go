package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator"
)

var Validate = validator.New()

const friendCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func ParseJSON(r *http.Request, payload any) error {
	if r.Body == nil {
		return fmt.Errorf("Missing request body")
	}
	return json.NewDecoder(r.Body).Decode(payload)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	var wrapped map[string]any

	switch status {
	case http.StatusOK, http.StatusCreated:
		wrapped = map[string]any{
			"status": "success",
			"data":   payload,
		}
	default:
		wrapped = map[string]any{
			"status":  "error",
			"message": payload,
		}
	}

	return json.NewEncoder(w).Encode(wrapped)
}

func WriteError(w http.ResponseWriter, status int, err error) {
	WriteJSON(w, status, err.Error())
}

func HashDeviceInfo(ip, userAgent string) string {
	data := ip + ":" + userAgent
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func GenerateFriendCode(length int) string {
	rand.Seed(time.Now().UnixNano())

	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteByte(friendCodeChars[rand.Intn(len(friendCodeChars))])
	}
	return sb.String()
}
