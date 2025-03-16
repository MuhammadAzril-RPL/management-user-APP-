package domain

import (
	"time"
)

type Authentication struct {
	ID       int
	UserID   int
	Password string
	Token    string
	LoginAt  time.Time
	LogoutAt time.Time
}

type AuthRepository interface {
	Create(auth *Authentication) error
	GetByUserID(userID int) (*Authentication, error)
	UpdateToken(userID int, token string, loginTime time.Time) error
	UpdateLogout(userID int, logoutTime time.Time) error
	VerifyToken(token string) (*Authentication, error)
}