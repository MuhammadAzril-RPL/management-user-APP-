package http

import (
	"net/http"
	"time"

	"main/internal/presenter"
	"main/internal/usecase"

	"github.com/gin-gonic/gin"
)

type UserController struct {
	userUseCase *usecase.UserUseCase
	authUseCase *usecase.AuthUseCase
}

func NewUserController(userUseCase *usecase.UserUseCase, authUseCase *usecase.AuthUseCase) *UserController {
	return &UserController{
		userUseCase: userUseCase,
		authUseCase: authUseCase,
	}
}

func (ctrl *UserController) Register(c *gin.Context) {
	var req presenter.RegisterUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := ctrl.userUseCase.Register(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, res)
}

func (ctrl *UserController) Login(c *gin.Context) {
	var req presenter.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := ctrl.authUseCase.Login(req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, res)
}

func (ctrl *UserController) GetProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	res, err := ctrl.userUseCase.GetProfile(userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, res)
}

func (ctrl *UserController) Logout(c *gin.Context) {
    userID, exists := c.Get("userID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return
    }
    auth, err := ctrl.authUseCase.GetAuthData(userID.(int))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not retrieve authentication data"})
        return
    }
    loginTime := auth.LoginAt
    logoutTime := time.Now()
    err = ctrl.authUseCase.Logout(userID.(int))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "logout successful",
        "login_at": loginTime,
        "logout_at": logoutTime,
    })
}

func (ctrl *UserController) AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header is required"})
            return
        }

        if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
            tokenString = tokenString[7:]
        }
	    
        userID, err := ctrl.authUseCase.ValidateToken(tokenString)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            return
        }
	    
        auth, err := ctrl.authUseCase.GetAuthData(userID)
        if err != nil || auth.Token != tokenString || !auth.LogoutAt.IsZero() {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token invalid or session expired"})
            return
        }

        c.Set("userID", userID)
        c.Next()
    }
}
