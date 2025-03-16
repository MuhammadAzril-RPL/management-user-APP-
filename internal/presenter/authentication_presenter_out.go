package presenter

import "time"

type AuthResponse struct {
	Token    string    `json:"token"`
	LoginAt  time.Time `json:"login_at"`
	LogoutAt time.Time `json:"logout_at,omitempty"`
}

type LoginResponse struct {
	Token string `json:"token"`
}