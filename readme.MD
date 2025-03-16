# User Management App

Aplikasi Manajemen Pengguna ini adalah aplikasi berbasis web yang memungkinkan pengguna untuk mendaftar, masuk, mendapatkan profil, dan keluar. Aplikasi ini dibangun menggunakan Go dan framework Gin.

## Fitur

- **Pendaftaran Pengguna**: Pengguna dapat mendaftar dengan email dan password.
- **Login**: Pengguna dapat masuk menggunakan email dan password.
- **Profil Pengguna**: Pengguna dapat melihat informasi profil mereka setelah login.
- **Logout**: Pengguna dapat keluar dari aplikasi.

## Alur Aplikasi

1. **Pendaftaran**:
   - Pengguna mengirimkan permintaan POST ke endpoint `/register` dengan data JSON yang berisi email dan password.
   - Jika pendaftaran berhasil, pengguna akan ditambahkan ke database.

2. **Login**:
   - Pengguna mengirimkan permintaan POST ke endpoint `/login` dengan data JSON yang berisi email dan password.
   - Jika login berhasil, pengguna akan menerima token yang dapat digunakan untuk mengakses endpoint yang dilindungi.

3. **Melihat Profil**:
   - Pengguna yang telah login dapat mengakses endpoint `/profile` untuk melihat informasi profil mereka.
   - Endpoint ini dilindungi oleh middleware autentikasi yang memverifikasi token.

4. **Logout**:
   - Pengguna dapat mengirimkan permintaan POST ke endpoint `/logout` untuk keluar dari aplikasi.
   - Token yang digunakan akan diinvalidasi.

## Cara Menggunakan dengan Postman

### Prasyarat

- Pastikan Anda telah menginstal Go di sistem Anda.
- Pastikan Anda telah menginstal Postman.

### Menggunakan Postman

1. **Pendaftaran Pengguna**
   - **Method**: POST
   - **URL**: `http://localhost:8080/register`
   - **Body**: Pilih `raw` dan `JSON`, lalu masukkan:
     ```json
     {
       "email": "user@example.com",
       "password": "password123"
     }
     ```

2. **Login Pengguna**
   - **Method**: POST
   - **URL**: `http://localhost:8080/login`
   - **Body**: Pilih `raw` dan `JSON`, lalu masukkan:
     ```json
     {
       "email": "user@example.com",
       "password": "password123"
     }
     ```

3. **Melihat Profil**
   - **Method**: GET
   - **URL**: `http://localhost:8080/profile`
   - **Headers**: Tambahkan header `Authorization` dengan nilai `Bearer <TOKEN>` (ganti `<TOKEN>` dengan token yang didapat dari login).

4. **Logout Pengguna**
   - **Method**: POST
   - **URL**: `http://localhost:8080/logout`
   - **Headers**: Tambahkan header `Authorization` dengan nilai `Bearer <TOKEN>` (ganti `<TOKEN>` dengan token yang didapat dari login).
