package org.lessons.java.spec.bibliojwt.model.dto;

/**
 * DTO per la risposta di autenticazione e refresh token.
 * 
 * UTILIZZO:
 * Ritornato dagli endpoint:
 * - POST /api/auth/login - Autenticazione iniziale
 * - POST /api/auth/refresh - Refresh access token
 * 
 * STRUTTURA RESPONSE:
 * {
 *   "token": "eyJhbGciOiJIUzUxMiJ9...",           // Access Token JWT (15 min)
 *   "refreshToken": "550e8400-e29b-41d4-...",    // Refresh Token UUID (7 giorni)
 *   "type": "Bearer",                             // Tipo di token
 *   "email": "user@example.com",                  // Email utente
 *   "role": "ROLE_USER",                          // Ruolo utente
 *   "message": "Login effettuato con successo",   // Messaggio opzionale
 *   "expiresIn": 900                             // Secondi prima della scadenza access token
 * }
 * 
 * DIFFERENZE TRA TOKEN:
 * 
 * ACCESS TOKEN (token):
 * - Formato: JWT (JSON Web Token)
 * - Durata: 15 minuti (configurable)
 * - Utilizzo: Ogni richiesta API nel header Authorization
 * - Revoca: Difficile (stateless), scade automaticamente
 * - Storage client: Memory (non localStorage per sicurezza)
 * 
 * REFRESH TOKEN (refreshToken):
 * - Formato: UUID random
 * - Durata: 7 giorni (configurable)
 * - Utilizzo: Solo per ottenere nuovo access token
 * - Revoca: Facile (memorizzato in database)
 * - Storage client: Secure storage (HttpOnly cookie o encrypted storage)
 * 
 * PERCHÉ DUE TOKEN?
 * - Access token breve = finestra di attacco ridotta se rubato
 * - Refresh token lungo = UX migliore (no login frequenti)
 * - Refresh token revocabile = controllo granulare sessioni
 * 
 * BEST PRACTICES CLIENT:
 * 1. Salva access token in memoria (variabile JS)
 * 2. Salva refresh token in HttpOnly cookie (o secure storage mobile)
 * 3. Su ogni richiesta API usa access token
 * 4. Se 401 Unauthorized → usa refresh token per ottenere nuovo access token
 * 5. Se refresh fallisce → redirect a login
 * 
 * @see RefreshTokenRequestDTO
 * @see org.lessons.java.spec.bibliojwt.service.JwtService
 * @see org.lessons.java.spec.bibliojwt.service.RefreshTokenService
 */
public class AuthResponseDTO {
    
    /**
     * Access Token JWT per autenticazione API.
     * Da inviare in ogni richiesta come: Authorization: Bearer <token>
     */
    private String token;
    
    /**
     * Refresh Token UUID per ottenere nuovo access token.
     * Da usare solo con endpoint /api/auth/refresh
     */
    private String refreshToken;
    
    /**
     * Tipo di token (sempre "Bearer" per JWT).
     */
    private String type = "Bearer";
    
    /**
     * Email dell'utente autenticato.
     */
    private String email;
    
    /**
     * Ruolo dell'utente (es. ROLE_ADMIN, ROLE_USER).
     */
    private String role;
    
    /**
     * Messaggio descrittivo opzionale.
     */
    private String message;
    
    /**
     * Secondi rimanenti prima della scadenza dell'access token.
     * Utile per client che vogliono refreshare proattivamente.
     */
    private Long expiresIn;

    // Constructors

    public AuthResponseDTO() {
    }

    /**
     * Constructor per login completo con tutti i campi.
     */
    public AuthResponseDTO(String token, String refreshToken, String email, String role, Long expiresIn) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.email = email;
        this.role = role;
        this.expiresIn = expiresIn;
    }

    /**
     * Constructor per response di solo refresh (senza ridondare email/role).
     */
    public AuthResponseDTO(String token, String refreshToken, Long expiresIn) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }

    // Getters and Setters

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }

    @Override
    public String toString() {
        return "AuthResponseDTO{" +
                "type='" + type + '\'' +
                ", email='" + email + '\'' +
                ", role='" + role + '\'' +
                ", message='" + message + '\'' +
                ", expiresIn=" + expiresIn +
                ", hasAccessToken=" + (token != null) +
                ", hasRefreshToken=" + (refreshToken != null) +
                '}';
    }
}

