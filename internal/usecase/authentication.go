package usecase

import (
	"errors"
	"time"

	"main/internal/domain"
	"main/internal/presenter"
)

type AuthUseCase struct {
	userRepo     domain.UserRepository
	authRepo     domain.AuthRepository
	passwordHash PasswordHasher
	tokenService TokenService
}

func NewAuthUseCase(userRepo domain.UserRepository, authRepo domain.AuthRepository,
	passwordHash PasswordHasher, tokenService TokenService) *AuthUseCase {
	return &AuthUseCase{
		userRepo:     userRepo,
		authRepo:     authRepo,
		passwordHash: passwordHash,
		tokenService: tokenService,
	}
}

func (uc *AuthUseCase) Login(req presenter.LoginRequest) (*presenter.LoginResponse, error) {
    user, err := uc.userRepo.GetByEmail(req.Email)
    if err != nil {
        return nil, err
    }

    auth, err := uc.authRepo.GetByUserID(user.ID)
    if err != nil {
        return nil, err
    }

    if !uc.passwordHash.CheckPasswordHash(req.Password, auth.Password) {
        return nil, errors.New("invalid credentials")
    }

    if auth.Token != "" && auth.LogoutAt.IsZero() {
        err = uc.authRepo.UpdateLogout(user.ID, time.Now())
        if err != nil {
            return nil, err
        }
    }
	
    token, err := uc.tokenService.GenerateToken(user.ID)
    if err != nil {
        return nil, err
    }

    err = uc.authRepo.UpdateToken(user.ID, token, time.Now())
    if err != nil {
        return nil, err
    }

    return &presenter.LoginResponse{
        Token: token,
    }, nil
}

func (uc *AuthUseCase) Logout(userID int) error {
	return uc.authRepo.UpdateLogout(userID, time.Now())
}

func (uc *AuthUseCase) ValidateToken(token string) (int, error) {
	return uc.tokenService.ValidateToken(token)
}

func (uc *AuthUseCase) GetAuthData(userID int) (*domain.Authentication, error) {
    return uc.authRepo.GetByUserID(userID)
}
