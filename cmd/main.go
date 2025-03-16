
package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"main/delivery/http"
	"main/infrastructure"
	"main/internal/usecase"
)

func main() {
	userRepo := infrastructure.NewInMemoryUserRepository()
	authRepo := infrastructure.NewInMemoryAuthRepository()
	jwtService := infrastructure.NewJWTService("your-secret-key", 24*time.Hour)
	passwordHasher := infrastructure.NewBcryptPasswordHasher(10)

	userUseCase := usecase.NewUserUseCase(userRepo, authRepo, passwordHasher, jwtService)
	authUseCase := usecase.NewAuthUseCase(userRepo, authRepo, passwordHasher, jwtService)
	
	userController := http.NewUserController(userUseCase, authUseCase)
	router := gin.Default()
	router.POST("/register", userController.Register)
	router.POST("/login", userController.Login)

	protected := router.Group("/")
	protected.Use(userController.AuthMiddleware())
	{
		protected.GET("/profile", userController.GetProfile)
		protected.POST("/logout", userController.Logout)
	}
	log.Println("Server is running on port 8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}