package org.lessons.java.spec.bibliojwt.service;

import org.lessons.java.spec.bibliojwt.exception.UserAlreadyExistsException;
import org.lessons.java.spec.bibliojwt.model.Role;
import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.model.dto.AuthResponseDTO;
import org.lessons.java.spec.bibliojwt.model.dto.LoginRequestDTO;
import org.lessons.java.spec.bibliojwt.model.dto.RegisterRequestDTO;
import org.lessons.java.spec.bibliojwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       AuthenticationManager authenticationManager,
                       RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.refreshTokenService = refreshTokenService;
    }

    @Transactional
    public User registerUser(RegisterRequestDTO request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Un utente con questa email esiste già");
        }

        Role role = Role.ROLE_USER;
        if (request.getRole() != null) {
            try {
                role = Role.valueOf(request.getRole().toUpperCase());
            } catch (IllegalArgumentException e) {
                // keep default
            }
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setRole(role);
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);

        return userRepository.save(user);
    }

    /**
     * Autentica l'utente e genera sia Access Token (JWT) che Refresh Token.
     * Il Refresh Token viene persistito nel database con audit trail (userAgent, ipAddress).
     * 
     * @param request LoginRequestDTO contenente email e password
     * @param userAgent User-Agent header del client (per audit)
     * @param ipAddress IP address del client (per audit)
     * @return AuthResponseDTO con access token (JWT, 15 min), refresh token (UUID, 7 giorni) ed expiresIn
     */
    public AuthResponseDTO authenticateAndGenerateToken(LoginRequestDTO request, String userAgent, String ipAddress) {
        // Autenticazione tramite Spring Security
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        // Genera Access Token (JWT)
        String accessToken = jwtService.generateToken(userDetails);
        String role = jwtService.extractRole(accessToken);
        
        // Ottieni l'entità User dal database per il Refresh Token
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("Utente non trovato dopo autenticazione"));
        
        // Genera Refresh Token (UUID, persistito nel database)
        org.lessons.java.spec.bibliojwt.model.RefreshToken refreshTokenEntity = refreshTokenService.createRefreshToken(user, userAgent, ipAddress);
        String refreshToken = refreshTokenEntity.getToken();
        
        // Calcola expiresIn in secondi (converti da millisecondi)
        Long expiresInSeconds = 900L; // 15 minuti = 900 secondi (access token)

        // Crea risposta completa con entrambi i token
        AuthResponseDTO authenticationResponse = new AuthResponseDTO();
        authenticationResponse.setToken(accessToken);
        authenticationResponse.setRefreshToken(refreshToken);
        authenticationResponse.setExpiresIn(expiresInSeconds);
        authenticationResponse.setType("Bearer");
        authenticationResponse.setEmail(userDetails.getUsername());
        authenticationResponse.setRole(role);
        authenticationResponse.setMessage("Login effettuato con successo");
        return authenticationResponse;
    }

    /**
     * Rinnova i token usando un Refresh Token valido.
     * Implementa il pattern di Token Rotation:
     * 1. Verifica il refresh token ricevuto (controllo validità, scadenza, revoca)
     * 2. Estrae l'utente associato al refresh token
     * 3. Genera un NUOVO access token JWT per l'utente
     * 4. Ruota il refresh token (revoca vecchio, crea nuovo)
     * 5. Ritorna entrambi i nuovi token
     * 
     * SECURITY: Se viene riusato un token già revocato (possibile attacco),
     * il sistema revoca TUTTI i refresh token dell'utente.
     * 
     * @param refreshTokenValue Il refresh token UUID da verificare
     * @param userAgent User-Agent del client per audit
     * @param ipAddress IP address del client per audit
     * @return AuthResponseDTO con i nuovi access token e refresh token
     */
    @Transactional
    public AuthResponseDTO refreshTokens(String refreshTokenValue, String userAgent, String ipAddress) {
        // Verifica il refresh token (controlla validità, scadenza, revoca)
        // Se il token è stato revocato e viene riusato, revoca TUTTI i token utente
        org.lessons.java.spec.bibliojwt.model.RefreshToken oldRefreshToken = 
                refreshTokenService.verifyRefreshToken(refreshTokenValue);
        
        // Estrai l'utente associato al refresh token
        User user = oldRefreshToken.getUser();
        
        // Genera NUOVO access token JWT
        org.springframework.security.core.userdetails.UserDetails userDetails = 
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getEmail())
                        .password(user.getPassword())
                        .authorities(user.getRole().name())
                        .build();
        
        String newAccessToken = jwtService.generateToken(userDetails);
        String role = jwtService.extractRole(newAccessToken);
        
        // Ruota il refresh token (revoca vecchio, crea nuovo) - SECURITY BEST PRACTICE
        org.lessons.java.spec.bibliojwt.model.RefreshToken newRefreshTokenEntity = 
                refreshTokenService.rotateRefreshToken(refreshTokenValue, userAgent, ipAddress);
        String newRefreshToken = newRefreshTokenEntity.getToken();
        
        // Calcola expiresIn
        Long expiresInSeconds = 900L; // 15 minuti
        
        // Crea risposta con i NUOVI token
        AuthResponseDTO authenticationResponse = new AuthResponseDTO();
        authenticationResponse.setToken(newAccessToken);
        authenticationResponse.setRefreshToken(newRefreshToken);
        authenticationResponse.setExpiresIn(expiresInSeconds);
        authenticationResponse.setType("Bearer");
        authenticationResponse.setEmail(user.getEmail());
        authenticationResponse.setRole(role);
        authenticationResponse.setMessage("Token rinnovato con successo");
        
        return authenticationResponse;
    }

    /**
     * Effettua il logout revocando il Refresh Token.
     * Dopo la revoca, il refresh token non potrà più essere usato per ottenere nuovi access token.
     * 
     * NOTA: L'Access Token JWT continuerà a funzionare fino alla scadenza naturale (15 minuti)
     * perché i JWT sono stateless. Per revocare anche l'access token sarebbe necessaria
     * una JWT blacklist (non implementata in questo esempio).
     * 
     * @param refreshTokenValue Il refresh token da revocare
     */
    @Transactional
    public void logout(String refreshTokenValue) {
        refreshTokenService.revokeToken(refreshTokenValue);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Utente non trovato"));
    }
}
