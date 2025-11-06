package br.edu.catolica.ms_auth.service;

import br.edu.catolica.ms_auth.dto.AuthDto;
import br.edu.catolica.ms_auth.model.Token;
import br.edu.catolica.ms_auth.model.User;
import br.edu.catolica.ms_auth.repository.TokenRepository;
import br.edu.catolica.ms_auth.repository.UserRepository;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.annotation.Transactional;
import java.util.Base64;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final LoginAttemptService loginAttemptService;
    private final ThrottlingService throttlingService;
    private final PasswordEncoder passwordEncoder;
    private final Cache passwordResetCache;



    public AuthService(UserRepository userRepository,
                       TokenRepository tokenRepository,
                       LoginAttemptService loginAttemptService,
                       ThrottlingService throttlingService,
                       PasswordEncoder passwordEncoder,
                       CacheManager cacheManager) {

        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.loginAttemptService = loginAttemptService;
        this.throttlingService = throttlingService;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetCache = cacheManager.getCache("passwordResetCache");

    }

    @Transactional
    public AuthDto.AuthResponse signUp(AuthDto.SignUpRequest request) {

        User newUser = new User();
        newUser.setEmail(request.email());
        newUser.setDocNumber(request.docNumber());
        newUser.setPassword(passwordEncoder.encode(request.password()));
        newUser.setUsername(request.username());
        newUser.setFullName(request.fullName());
        newUser.setLoggedin(true);

        User savedUser = userRepository.save(newUser);
        return new AuthDto.AuthResponse(generateAndSaveToken(savedUser));
    }

    @Transactional
    public AuthDto.AuthResponse login(AuthDto.LoginRequest request) {

        String loginKey = request.login();
        if (loginAttemptService.isBlocked(loginKey)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas tentativas falhas. Tente novamente em 10 minutos.");
        }

        User user = userRepository.findByEmail(loginKey)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email ou senha inválidos"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            loginAttemptService.loginFailed(loginKey);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email ou senha inválidos");
        }

        loginAttemptService.loginSucceeded(loginKey);
        user.setLoggedin(true);
        User savedUser = userRepository.save(user);
        return new AuthDto.AuthResponse(generateAndSaveToken(savedUser));
    }

    @Transactional(readOnly = true)
    public AuthDto.PasswordResetResponse requestPasswordReset(AuthDto.PasswordResetRequest request) {
        User user = userRepository.findByEmailAndDocNumber(request.email(), request.docNumber())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado com os dados fornecidos"));

        String resetToken = UUID.randomUUID().toString();

        passwordResetCache.put(resetToken, user.getEmail());

        return new AuthDto.PasswordResetResponse(resetToken);
    }

    @Transactional
    public void performPasswordReset(AuthDto.PasswordResetPerformRequest request) {

        String resetToken = request.resetToken();

        String userEmail = passwordResetCache.get(resetToken, String.class);


        if (userEmail == null) {

            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token de reset inválido ou expirado.");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado."));

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        passwordResetCache.evict(resetToken);
    }

    @Transactional
    public void logout(String token) {
        Token storedToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token inválido"));
        User user = storedToken.getUser();
        user.setLoggedin(false);
        userRepository.save(user);
        tokenRepository.delete(storedToken);
    }

    public AuthDto.UserResponse getUserByToken(String token) {

        String throttleKey = token;
        if (throttlingService.isThrottled(throttleKey)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas requisições. Tente novamente em 1 minuto.");
        }
        throttlingService.incrementAttempt(throttleKey);

        User user = tokenRepository.findByToken(token)
                .map(Token::getUser)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token inválido"));

        return new AuthDto.UserResponse(
                user.getId(),
                user.getEmail(),
                user.getUsername(),
                user.getFullName()
        );
    }

    private String generateAndSaveToken(User user) {
        String tokenData = user.getEmail() + ":" + user.getDocNumber();
        String tokenString = Base64.getEncoder().encodeToString(tokenData.getBytes());

        tokenRepository.deleteAllByUserId(user.getId());
        tokenRepository.flush();

        Token token = new Token(user, tokenString);
        tokenRepository.save(token);
        return tokenString;
    }

    public String extractToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("SDWork ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Header de autorização inválido ou ausente");
        }
        return authorizationHeader.substring(7);
    }
}