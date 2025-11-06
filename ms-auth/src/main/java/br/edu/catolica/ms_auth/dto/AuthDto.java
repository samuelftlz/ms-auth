package br.edu.catolica.ms_auth.dto;

public class AuthDto {

    public record LoginRequest(String login, String password) {}
    public record SignUpRequest(String email, String docNumber, String password, String username, String fullName) {}
    public record AuthResponse(String token) {}
    public record PasswordResetRequest(String email, String docNumber) {}
    public record PasswordResetResponse(String resetToken) {}
    public record PasswordResetPerformRequest(String resetToken, String newPassword) {}
    public record UserResponse(Integer id, String email, String username, String fullName) {}

}