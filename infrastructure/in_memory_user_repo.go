package infrastructure

import (
	"errors"
	"sync"
	"time"

	"main/internal/domain"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type InMemoryUserRepository struct {
	users      map[int]*domain.User
	counter    int
	emailIndex map[string]int
	mu         sync.RWMutex
}

func NewInMemoryUserRepository() *InMemoryUserRepository {
	return &InMemoryUserRepository{
		users:      make(map[int]*domain.User),
		emailIndex: make(map[string]int),
		counter:    1,
	}
}

func (r *InMemoryUserRepository) Create(user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.emailIndex[user.Email]; exists {
		return errors.New("email already exists")
	}

	user.ID = r.counter
	r.users[user.ID] = user
	r.emailIndex[user.Email] = user.ID
	r.counter++
	return nil
}

func (r *InMemoryUserRepository) GetByID(id int) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, exists := r.users[id]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (r *InMemoryUserRepository) GetByEmail(email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, exists := r.emailIndex[email]
	if !exists {
		return nil, errors.New("user not found")
	}
	return r.users[id], nil
}

type InMemoryAuthRepository struct {
	auths             map[int]*domain.Authentication
	counter           int
	tokenMap          map[string]int  // map token to userID
	invalidatedTokens map[string]bool // set of invalidated tokens
	mu                sync.RWMutex
}

func NewInMemoryAuthRepository() *InMemoryAuthRepository {
	return &InMemoryAuthRepository{
		auths:             make(map[int]*domain.Authentication),
		tokenMap:          make(map[string]int),
		invalidatedTokens: make(map[string]bool),
		counter:           1,
	}
}

func (r *InMemoryAuthRepository) Create(auth *domain.Authentication) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	auth.ID = r.counter
	r.auths[auth.UserID] = auth
	r.counter++
	return nil
}

func (r *InMemoryAuthRepository) GetByUserID(userID int) (*domain.Authentication, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	auth, exists := r.auths[userID]
	if !exists {
		return nil, errors.New("authentication not found")
	}
	return auth, nil
}

func (r *InMemoryAuthRepository) UpdateToken(userID int, token string, loginTime time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	auth, exists := r.auths[userID]
	if !exists {
		return errors.New("authentication not found")
	}

	if auth.Token != "" {
		delete(r.tokenMap, auth.Token)
	}

	auth.Token = token
	auth.LoginAt = loginTime
	auth.LogoutAt = time.Time{}
	r.tokenMap[token] = userID
	return nil
}

func (r *InMemoryAuthRepository) UpdateLogout(userID int, logoutTime time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	auth, exists := r.auths[userID]
	if !exists {
		return errors.New("authentication not found")
	}

	// Tandai token sebagai tidak valid
	if auth.Token != "" {
		oldToken := auth.Token // Simpan token lama
		r.invalidatedTokens[oldToken] = true
		// Hapus dari tokenMap aktif
		delete(r.tokenMap, oldToken)
	}

	// Catat waktu logout
	auth.LogoutAt = logoutTime
	// Bersihkan token
	auth.Token = "" // Hapus token

	return nil
}

// infrastructure/in_memory_user_repo.go - Perbaikan fungsi VerifyToken
func (r *InMemoryAuthRepository) VerifyToken(token string) (*domain.Authentication, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Periksa apakah token telah diinvalidasi
	if _, invalid := r.invalidatedTokens[token]; invalid {
		return nil, errors.New("token has been invalidated")
	}

	// Cek apakah token ada di map aktif
	userID, exists := r.tokenMap[token]
	if !exists {
		return nil, errors.New("invalid token")
	}

	auth, exists := r.auths[userID]
	if !exists {
		return nil, errors.New("authentication not found")
	}

	// Periksa apakah token cocok dengan yang tersimpan
	if auth.Token != token {
		return nil, errors.New("token mismatch")
	}

	return auth, nil
}

type JWTService struct {
	secretKey string
	ttl       time.Duration
}

type JWTClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func NewJWTService(secretKey string, ttl time.Duration) *JWTService {
	return &JWTService{secretKey: secretKey, ttl: ttl}
}

func (s *JWTService) GenerateToken(userID int) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}

func (s *JWTService) ValidateToken(tokenString string) (int, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.secretKey), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims.UserID, nil
	}
	return 0, errors.New("invalid token")
}

type BcryptPasswordHasher struct {
	cost int
}

func NewBcryptPasswordHasher(cost int) *BcryptPasswordHasher {
	return &BcryptPasswordHasher{cost: cost}
}

func (h *BcryptPasswordHasher) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h *BcryptPasswordHasher) CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
