package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argon2id.DefaultParams)
}

func CheckPasswordHash(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := &jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tString, err := token.SignedString([]byte(tokenSecret))
	return tString, err
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	}
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, keyFunc)
	if err != nil {
		return uuid.UUID{}, err
	}
	uid, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	return uuid.Parse(uid)
}

func GetBearerToken(headers http.Header) (string, error) {
	headerValue := headers.Get("Authorization")
	token, foundPrefix := strings.CutPrefix(headerValue, "Bearer ")
	if !foundPrefix || len(token) < 1 {
		return "", errors.New("authorization token not found")
	}
	return token, nil
}

func MakeRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
