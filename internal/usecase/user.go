package usecase

import (
	"errors"
	"time"

	"main/internal/domain"
	"main/internal/presenter"
)

type UserUseCase struct {
	userRepo     domain.UserRepository
	authRepo     domain.AuthRepository
	passwordHash PasswordHasher
	tokenService TokenService
}

type PasswordHasher interface {
	HashPassword(password string) (string, error)
	CheckPasswordHash(password, hash string) bool
}

type TokenService interface {
	GenerateToken(userID int) (string, error)
	ValidateToken(token string) (int, error)
}

func NewUserUseCase(userRepo domain.UserRepository, authRepo domain.AuthRepository, 
	passwordHash PasswordHasher, tokenService TokenService) *UserUseCase {
	return &UserUseCase{
		userRepo:     userRepo,
		authRepo:     authRepo,
		passwordHash: passwordHash,
		tokenService: tokenService,
	}
}

func (uc *UserUseCase) Register(req presenter.RegisterUserRequest) (*presenter.UserResponse, error) {
	existingUser, _ := uc.userRepo.GetByEmail(req.Email)
	if existingUser != nil {
		return nil, errors.New("email already registered")
	}

	hashedPassword, err := uc.passwordHash.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	user := &domain.User{
		Name:      req.Name,
		Email:     req.Email,
		CreatedAt: time.Now(),
	}

	err = uc.userRepo.Create(user)
	if err != nil {
		return nil, err
	}

	auth := &domain.Authentication{
		UserID:   user.ID,
		Password: hashedPassword,
	}

	err = uc.authRepo.Create(auth)
	if err != nil {
		return nil, err
	}

	return &presenter.UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (uc *UserUseCase) GetProfile(userID int) (*presenter.UserResponse, error) {
	user, err := uc.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	return &presenter.UserResponse{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}, nil
}