package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "simple password",
			password: "password123",
		},
		{
			name:     "complex password",
			password: "P@ssw0rd!#$%^&*()",
		},
		{
			name:     "empty password",
			password: "",
		},
		{
			name:     "long password",
			password: "thisIsAVeryLongPasswordWithLotsOfCharactersThatGoesOnAndOnAndOn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if err != nil {
				t.Fatalf("HashPassword() error = %v", err)
			}
			if hash == "" {
				t.Error("HashPassword() returned empty hash")
			}
			if hash == tt.password {
				t.Error("HashPassword() returned unhashed password")
			}
		})
	}
}

func TestHashPasswordDifferentHashes(t *testing.T) {
	password := "samepassword"
	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash1 == hash2 {
		t.Error("HashPassword() should produce different hashes due to salt")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
		},
		{
			name:     "incorrect password",
			password: "wrongpassword",
			hash:     hash,
			want:     false,
		},
		{
			name:     "empty password against hash",
			password: "",
			hash:     hash,
			want:     false,
		},
		{
			name:     "case sensitive password",
			password: "TESTPASSWORD123",
			hash:     hash,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordHash(tt.password, tt.hash)
			if err != nil {
				t.Fatalf("CheckPasswordHash() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("CheckPasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	tests := []struct {
		name        string
		userID      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration
		wantErr     bool
	}{
		{
			name:        "valid JWT creation",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   expiresIn,
			wantErr:     false,
		},
		{
			name:        "short expiration",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   time.Second,
			wantErr:     false,
		},
		{
			name:        "long expiration",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   24 * time.Hour,
			wantErr:     false,
		},
		{
			name:        "empty secret",
			userID:      userID,
			tokenSecret: "",
			expiresIn:   expiresIn,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := MakeJWT(tt.userID, tt.tokenSecret, tt.expiresIn)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token == "" {
				t.Error("MakeJWT() returned empty token")
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	validToken, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	expiredToken, err := MakeJWT(userID, tokenSecret, -time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	differentSecretToken, err := MakeJWT(userID, "different-secret", expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	tests := []struct {
		name        string
		tokenString string
		tokenSecret string
		wantUserID  uuid.UUID
		wantErr     bool
	}{
		{
			name:        "valid token",
			tokenString: validToken,
			tokenSecret: tokenSecret,
			wantUserID:  userID,
			wantErr:     false,
		},
		{
			name:        "expired token",
			tokenString: expiredToken,
			tokenSecret: tokenSecret,
			wantUserID:  uuid.UUID{},
			wantErr:     true,
		},
		{
			name:        "wrong secret",
			tokenString: differentSecretToken,
			tokenSecret: tokenSecret,
			wantUserID:  uuid.UUID{},
			wantErr:     true,
		},
		{
			name:        "invalid token format",
			tokenString: "invalid.token.string",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.UUID{},
			wantErr:     true,
		},
		{
			name:        "empty token",
			tokenString: "",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.UUID{},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.tokenString, tt.tokenSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestJWTRoundTrip(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	validatedUserID, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}

	if validatedUserID != userID {
		t.Errorf("Round trip failed: got %v, want %v", validatedUserID, userID)
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	password := "mySecurePassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	match, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("CheckPasswordHash() error = %v", err)
	}

	if !match {
		t.Error("Round trip failed: password does not match hash")
	}
}
