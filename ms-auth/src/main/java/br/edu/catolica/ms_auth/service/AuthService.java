package br.edu.catolica.ms_auth.service;

import br.edu.catolica.ms_auth.dto.AuthDto;
import br.edu.catolica.ms_auth.model.Token;
import br.edu.catolica.ms_auth.model.User;
import br.edu.catolica.ms_auth.repository.TokenRepository;
import br.edu.catolica.ms_auth.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.annotation.Transactional;
import java.util.Base64;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final LoginAttemptService loginAttemptService;

    public AuthService(UserRepository userRepository,
                       TokenRepository tokenRepository,
                       LoginAttemptService loginAttemptService) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.loginAttemptService = loginAttemptService;
    }

    @Transactional
    public AuthDto.AuthResponse signUp(AuthDto.SignUpRequest request) {

        User newUser = new User();
        newUser.setEmail(request.email());
        newUser.setDocNumber(request.docNumber());
        newUser.setPassword(request.password());
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

        if (!user.getPassword().equals(request.password())) {

            loginAttemptService.loginFailed(loginKey);

            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email ou senha inválidos");
        }

        loginAttemptService.loginSucceeded(loginKey);

        user.setLoggedin(true);
        User savedUser = userRepository.save(user);
        return new AuthDto.AuthResponse(generateAndSaveToken(savedUser));
    }

    @Transactional
    public AuthDto.AuthResponse recoverPassword(AuthDto.RecoverPasswordRequest request) {

        User user = userRepository.findByEmailAndDocNumber(request.email(), request.document())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado com os dados fornecidos"));
        user.setPassword(request.newPassword());
        User savedUser = userRepository.save(user);
        return new AuthDto.AuthResponse(generateAndSaveToken(savedUser));
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

    public User getUserByToken(String token) {

        return tokenRepository.findByToken(token)
                .map(Token::getUser)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token inválido"));
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