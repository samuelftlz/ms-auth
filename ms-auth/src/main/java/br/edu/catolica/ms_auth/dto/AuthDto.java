package br.edu.catolica.ms_auth.dto;

public class AuthDto {
    public record LoginRequest(String login, String password) {}
    public record SignUpRequest(String email, String docNumber, String password, String username, String fullName) {}
    public record RecoverPasswordRequest(String document, String email, String newPassword) {}
    public record AuthResponse(String token) {}
}