package org.genesiscode.jwtpractice.auth;

import lombok.RequiredArgsConstructor;
import org.genesiscode.jwtpractice.config.JwtService;
import org.genesiscode.jwtpractice.token.Token;
import org.genesiscode.jwtpractice.token.TokenRepository;
import org.genesiscode.jwtpractice.token.TokenType;
import org.genesiscode.jwtpractice.user.Role;
import org.genesiscode.jwtpractice.user.User;
import org.genesiscode.jwtpractice.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager manager;

    public AuthenticationResponse register(RegisterRequest request) {
        // TODO: show me 403 forbidden and better logs when happens its
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException(String.format("Username with email %s already exists", request.getEmail()));
        }

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        User savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        saveUserToken(savedUser, jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();

        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        manager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setRevoked(true);
            token.setExpired(true);
        });
        tokenRepository.saveAll(validUserTokens);

    }
}
