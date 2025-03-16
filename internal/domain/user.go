// internal/domain/user.go
package domain

import (
	"time"
)

type User struct {
	ID        int
	Name      string
	Email     string
	CreatedAt time.Time
}


type UserRepository interface {
	Create(user *User) error
	GetByID(id int) (*User, error)
	GetByEmail(email string) (*User, error)
}