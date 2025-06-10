package auth

import "golang.org/x/crypto/bcrypt"

const bcryptCost = 12

func HashedPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}
