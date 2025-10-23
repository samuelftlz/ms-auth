package br.edu.catolica.ms_auth.controller;

import br.edu.catolica.ms_auth.dto.AuthDto;
import br.edu.catolica.ms_auth.model.User;
import br.edu.catolica.ms_auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthDto.AuthResponse> signUp(@RequestBody AuthDto.SignUpRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.signUp(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthDto.AuthResponse> login(@RequestBody AuthDto.LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/recuperar-senha")
    public ResponseEntity<AuthDto.AuthResponse> recoverPassword(@RequestBody AuthDto.RecoverPasswordRequest request) {
        return ResponseEntity.ok(authService.recoverPassword(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorizationHeader) {
        String token = authService.extractToken(authorizationHeader);
        authService.logout(token);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    public ResponseEntity<User> getMe(@RequestHeader("Authorization") String authorizationHeader) {
        String token = authService.extractToken(authorizationHeader);
        User user = authService.getUserByToken(token);
        return ResponseEntity.ok(user);
    }

}