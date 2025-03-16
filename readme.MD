# User Management App

## Deskripsi
User Management App adalah aplikasi yang memungkinkan pengguna untuk mendaftar, masuk, mendapatkan profil, dan keluar. Aplikasi ini dibangun menggunakan Go dan framework Gin untuk menangani HTTP routing.

## Fitur
- **Pendaftaran Pengguna**: Pengguna dapat mendaftar dengan memberikan email dan password.
- **Login**: Pengguna dapat masuk ke aplikasi menggunakan email dan password.
- **Profil Pengguna**: Pengguna dapat melihat informasi profil mereka setelah login.
- **Logout**: Pengguna dapat keluar dari aplikasi.

## Arsitektur
Aplikasi ini terdiri dari beberapa komponen utama:

1. **Router**: Mengatur rute HTTP untuk berbagai endpoint.
2. **Controller**: Mengelola logika bisnis untuk setiap endpoint.
3. **UseCase**: Mengelola interaksi antara controller dan repositori.
4. **Repository**: Menyimpan dan mengelola data pengguna dan autentikasi dalam memori.

## Alur Aplikasi

### 1. Inisialisasi
Aplikasi dimulai dengan menginisialisasi repositori pengguna dan autentikasi, serta layanan JWT dan password hashing.

```go
userRepo := infrastructure.NewInMemoryUserRepository()
authRepo := infrastructure.NewInMemoryAuthRepository()
jwtService := infrastructure.NewJWTService("your-secret-key", 24*time.Hour)
passwordHasher := infrastructure.NewBcryptPasswordHasher(10)
```

### 2. Penggunaan UseCase
Setelah repositori dan layanan diinisialisasi, kita membuat instance dari `UserUseCase` dan `AuthUseCase` yang akan digunakan oleh controller.

```go
userUseCase := usecase.NewUserUseCase(userRepo, authRepo, passwordHasher, jwtService)
authUseCase := usecase.NewAuthUseCase(userRepo, authRepo, passwordHasher, jwtService)
```

### 3. Controller
Controller `UserController` dibuat dengan menghubungkan use case yang telah dibuat sebelumnya.

```go
userController := http.NewUserController(userUseCase, authUseCase)
```

### 4. Routing
Router Gin digunakan untuk mendefinisikan endpoint yang dapat diakses oleh pengguna. Endpoint yang tersedia meliputi:
- `POST /register`: Untuk mendaftar pengguna baru.
- `POST /login`: Untuk masuk ke aplikasi.
- `GET /profile`: Untuk mendapatkan informasi profil pengguna (diperlukan autentikasi).
- `POST /logout`: Untuk keluar dari aplikasi (diperlukan autentikasi).

```go
router.POST("/register", userController.Register)
router.POST("/login", userController.Login)

protected := router.Group("/")
protected.Use(userController.AuthMiddleware())
{
    protected.GET("/profile", userController.GetProfile)
    protected.POST("/logout", userController.Logout)
}
```

### 5. Menjalankan Server
Akhirnya, server dijalankan pada port 8080.

```go
if err := router.Run(":8080"); err != nil {
    log.Fatalf("Failed to start server: %v", err)
}
```

## Cara Menjalankan Aplikasi
1. Pastikan Anda memiliki Go terinstal di sistem Anda.
2. Clone repositori ini.
3. Jalankan perintah berikut untuk memulai aplikasi:
   ```bash
   go run cmd/main.go
   ```
4. Akses aplikasi melalui `http://localhost:8080`.

## Catatan
- Pastikan untuk mengganti `your-secret-key` dengan kunci rahasia yang aman untuk JWT.
- Aplikasi ini menggunakan penyimpanan dalam memori, sehingga data tidak akan persisten setelah aplikasi dimatikan.
