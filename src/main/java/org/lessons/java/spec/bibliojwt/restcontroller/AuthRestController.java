package org.lessons.java.spec.bibliojwt.restcontroller;

import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.model.dto.ApiResponseDTO;
import org.lessons.java.spec.bibliojwt.model.dto.AuthResponseDTO;
import org.lessons.java.spec.bibliojwt.model.dto.LoginRequestDTO;
import org.lessons.java.spec.bibliojwt.model.dto.RegisterRequestDTO;
import org.lessons.java.spec.bibliojwt.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller per gestire l'autenticazione JWT.
 * 
 * ENDPOINT PUBBLICI:
 * Questi endpoint sono accessibili senza autenticazione.
 * Sono configurati in SecurityConfig come permitAll().
 * 
 * PATH BASE: /api/auth
 * 
 * ENDPOINT DISPONIBILI:
 * - POST /api/auth/register - Registra nuovo utente
 * - POST /api/auth/login - Login e generazione JWT
 * 
 * FLUSSO TIPICO:
 * 
 * 1. REGISTRAZIONE:
 *    Client → POST /api/auth/register → Server
 *    Server valida dati → Crea utente → Salva in DB
 *    Server → Risposta successo → Client
 * 
 * 2. LOGIN:
 *    Client → POST /api/auth/login → Server
 *    Server valida credenziali → Genera JWT
 *    Server → JWT token → Client
 * 
 * 3. USO TOKEN:
 *    Client → GET /api/student/profile + "Authorization: Bearer <token>"
 *    Server valida token → Esegue operazione → Risposta
 * 
 * FORMATO RISPOSTE:
 * Tutte le risposte seguono un formato consistente per facilitare
 * il parsing lato client e fornire un'esperienza API uniforme.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j // private static final org.slf4j.Logger log = LoggerFactory.getLogger(AuthRestController.class);
public class AuthRestController {
    

    private final UserService userService;
    
    /**
     * Endpoint per registrare un nuovo utente nel sistema.
     * 
     * METODO: POST
     * PATH: /api/auth/register
     * BODY: JSON con dati utente
     * AUTENTICAZIONE: Non richiesta (pubblico)
     * 
     * VALIDAZIONE:
     * La validazione viene effettuata automaticamente da Spring
     * grazie all'annotazione @Valid sul parametro.
     * Le constraint sono definite nel DTO RegisterRequestDTO:
     * - Email deve essere valida
     * - Password almeno 6 caratteri
     * - Nome e cognome obbligatori
     * 
     * Se la validazione fallisce, Spring ritorna automaticamente
     * un errore 400 Bad Request con i dettagli degli errori.
     * 
     * PROCESSO:
     * 1. Riceve i dati di registrazione nel body
     * 2. @Valid attiva la validazione Bean Validation
     * 3. UserService verifica se email esiste già
     * 4. Se non esiste, crea nuovo utente con password hashata
     * 5. Salva nel database
     * 6. Ritorna risposta di successo
     * 
     * ESEMPIO RICHIESTA:
     * POST http://localhost:8080/api/auth/register
     * Content-Type: application/json
     * 
     * {
     *   "email": "nuovo@univ.it",
     *   "password": "password123",
     *   "firstName": "Mario",
     *   "lastName": "Rossi",
     *   "role": "ROLE_USER"
     * }
     * 
     * ESEMPIO RISPOSTA SUCCESSO (201 Created):
     * {
     *   "success": true,
     *   "message": "Utente registrato con successo",
     *   "data": null
     * }
     * 
     * ESEMPIO RISPOSTA ERRORE (409 Conflict):
     * {
     *   "success": false,
     *   "message": "Un utente con questa email esiste già",
     *   "data": null
     * }
     * 
     * @param request DTO con dati di registrazione validati
     * @return ResponseEntity con ApiResponseDTO e status code appropriato
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDTO> register(
            @Valid @RequestBody RegisterRequestDTO request
    ) {
        log.info("Tentativo registrazione per email: {}", request.getEmail());
        
        try {
            // Delega al service la logica di business
            // Il service verifica unicità email e crea l'utente
            User newUser = userService.registerUser(request);
            
            log.info("Utente registrato con successo: {}", newUser.getEmail());
            
            // Costruisci risposta di successo
            ApiResponseDTO response = new ApiResponseDTO(
                true,
                "Utente registrato con successo",
                null  // Non ritorniamo dati sensibili come password
            );
            
            // Ritorna 201 Created (standard per creazione risorsa)
            return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
                
        } catch (Exception e) {
            // Le eccezioni specifiche (UserAlreadyExistsException)
            // sono gestite dal GlobalExceptionHandler
            // Qui gestiamo solo errori non previsti
            log.error("Errore durante registrazione: {}", e.getMessage());
            throw e;  // Rilancia per GlobalExceptionHandler
        }
    }
    
    /**
     * Endpoint per effettuare login e ottenere un token JWT.
     * 
     * METODO: POST
     * PATH: /api/auth/login
     * BODY: JSON con credenziali
     * AUTENTICAZIONE: Non richiesta (pubblico)
     * 
     * PROCESSO DI LOGIN:
     * 1. Client invia email e password
     * 2. Server valida formato dati (@Valid)
     * 3. UserService usa AuthenticationManager per validare credenziali
     * 4. AuthenticationManager delega a:
     *    - UserDetailsService per caricare utente
     *    - PasswordEncoder per verificare password
     * 5. Se credenziali valide:
     *    - JwtService genera nuovo token JWT
     *    - Token include username, ruolo, scadenza
     *    - Token viene firmato con chiave segreta
     * 6. Server ritorna token al client
     * 7. Client salva token (localStorage, sessionStorage, memoria)
     * 8. Per richieste successive, client invia:
     *    Authorization: Bearer <token>
     * 
     * SICUREZZA:
     * - Password NON viene mai ritornata
     * - Token ha scadenza (configurabile in application.properties)
     * - Token è firmato (non può essere modificato)
     * - Ogni login fallito viene loggato (importante per sicurezza)
     * 
     * ESEMPIO RICHIESTA:
     * POST http://localhost:8080/api/auth/login
     * Content-Type: application/json
     * 
     * {
     *   "email": "admin@univ.it",
     *   "password": "admin123"
     * }
     * 
     * ESEMPIO RISPOSTA SUCCESSO (200 OK):
     * {
     *   "token": "eyJhbGciOiJIUzUxMiJ9.eyJyb2xlIjoiUk9MRV9BRE1JTi...",
     *   "type": "Bearer",
     *   "email": "admin@univ.it",
     *   "role": "ROLE_ADMIN",
     *   "message": "Login effettuato con successo"
     * }
     * 
     * ESEMPIO RISPOSTA ERRORE (401 Unauthorized):
     * {
     *   "success": false,
     *   "message": "Email o password non corretti",
     *   "data": null
    /**
     * ENDPOINT: POST /api/auth/login
     * 
     * Autentica l'utente e restituisce sia Access Token (JWT) che Refresh Token (UUID).
     * 
     * REQUEST BODY (JSON):
     * {
     *   "email": "user@example.com",
     *   "password": "password123"
     * }
     * 
     * RESPONSE (JSON):
     * {
     *   "token": "eyJhbGciOiJIUzI1NiJ9...",     // Access Token JWT (15 minuti)
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000",  // Refresh Token UUID (7 giorni)
     *   "expiresIn": 900,                       // Secondi alla scadenza del token
     *   "type": "Bearer",
     *   "email": "user@example.com",
     *   "role": "ROLE_USER",
     *   "message": "Login effettuato con successo"
     * }
     * 
     * COME USARE I TOKEN:
     * 1. Access Token: Include in ogni richiesta protetta nell'header Authorization:
     *    Authorization: Bearer {access_token}
     * 
     * 2. Refresh Token: Quando l'Access Token scade, usa il Refresh Token per ottenerne uno nuovo
     *    chiamando POST /api/auth/refresh con il refresh token
     * 
     * SICUREZZA:
     * - Il Refresh Token viene salvato nel database con audit trail (User-Agent, IP)
     * - Massimo 5 refresh token attivi per utente
     * - Token rotation: ogni refresh genera un nuovo token e revoca il vecchio
     * - Reuse detection: se un token revocato viene riusato, TUTTI i token dell'utente vengono revocati
     * 
     * @param request DTO con email e password
     * @param httpRequest HttpServletRequest per estrarre User-Agent e IP address
     * @return ResponseEntity con AuthResponseDTO contenente access token, refresh token ed expiresIn
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO request,
            HttpServletRequest httpRequest
    ) {
        log.info("Tentativo login per email: {}", request.getEmail());
        
        try {
            // Estrai User-Agent e IP Address per audit trail del Refresh Token
            String userAgent = httpRequest.getHeader("User-Agent");
            if (userAgent == null) {
                userAgent = "Unknown";
            }
            
            String ipAddress = httpRequest.getRemoteAddr();
            
            // Delega al service l'autenticazione e generazione token
            // Il service:
            // 1. Usa AuthenticationManager per validare credenziali
            // 2. Genera Access Token JWT (15 minuti)
            // 3. Genera Refresh Token UUID e lo salva nel database (7 giorni)
            // 4. Ritorna AuthResponseDTO con entrambi i token
            AuthResponseDTO response = userService
                .authenticateAndGenerateToken(request, userAgent, ipAddress);
            
            log.info("Login effettuato con successo per: {} - Generati Access Token e Refresh Token", 
                    request.getEmail());
            
            // Ritorna 200 OK con entrambi i token
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            // Le BadCredentialsException sono gestite da GlobalExceptionHandler
            // Viene ritornato 401 Unauthorized
            log.warn("Login fallito per email: {}", request.getEmail());
            throw e;  // Rilancia per GlobalExceptionHandler
        }
    }
    
    /**
     * ENDPOINT: POST /api/auth/refresh
     * 
     * Rinnova l'Access Token usando un Refresh Token valido.
     * Implementa il pattern di Token Rotation per maggiore sicurezza:
     * - Verifica il refresh token ricevuto
     * - Genera un NUOVO access token JWT
     * - Genera un NUOVO refresh token UUID
     * - Revoca il VECCHIO refresh token
     * 
     * SECURITY BEST PRACTICE: Token Rotation
     * Ogni volta che un refresh token viene usato, viene generato un nuovo refresh token
     * e il vecchio viene revocato. Questo previene il riuso di refresh token rubati.
     * 
     * REUSE DETECTION:
     * Se un refresh token GIÀ REVOCATO viene riusato (possibile attacco), il sistema
     * revoca TUTTI i refresh token dell'utente per sicurezza.
     * 
     * REQUEST BODY (JSON):
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     * 
     * RESPONSE (JSON):
     * {
     *   "token": "eyJhbGciOiJIUzI1NiJ9...",     // NUOVO Access Token JWT (15 minuti)
     *   "refreshToken": "660f9511-f30c-52e5-b827-557766551111",  // NUOVO Refresh Token UUID (7 giorni)
     *   "expiresIn": 900,                       // Secondi alla scadenza del token
     *   "type": "Bearer",
     *   "email": "user@example.com",
     *   "role": "ROLE_USER",
     *   "message": "Token rinnovato con successo"
     * }
     * 
     * ERRORI:
     * - 401 Unauthorized: Refresh token non valido, scaduto o revocato
     * - 403 Forbidden: Refresh token riusato (possibile attacco) - TUTTI i token utente revocati
     * 
     * @param request DTO contenente il refresh token
     * @param httpRequest HttpServletRequest per estrarre User-Agent e IP
     * @return ResponseEntity con AuthResponseDTO contenente i NUOVI access token e refresh token
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponseDTO> refreshToken(
            @Valid @RequestBody org.lessons.java.spec.bibliojwt.model.dto.RefreshTokenRequestDTO request,
            HttpServletRequest httpRequest
    ) {
        log.info("Richiesta refresh token");
        
        try {
            // Estrai User-Agent e IP per audit trail del nuovo refresh token
            String userAgent = httpRequest.getHeader("User-Agent");
            if (userAgent == null) {
                userAgent = "Unknown";
            }
            String ipAddress = httpRequest.getRemoteAddr();
            
            // Crea un service method che gestisce il refresh
            AuthResponseDTO response = userService.refreshTokens(
                    request.getRefreshToken(), 
                    userAgent, 
                    ipAddress
            );
            
            log.info("Token rinnovato con successo per utente: {}", response.getEmail());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.warn("Refresh token fallito: {}", e.getMessage());
            throw e;  // Gestito da GlobalExceptionHandler
        }
    }
    
    /**
     * ENDPOINT: POST /api/auth/logout
     * 
     * Effettua il logout revocando il Refresh Token dell'utente.
     * Dopo il logout, il refresh token non può più essere usato per ottenere nuovi access token.
     * 
     * NOTE:
     * - L'Access Token JWT continuerà a funzionare fino alla scadenza naturale (15 minuti)
     *   perché i JWT sono stateless e non possono essere revocati senza una blacklist
     * - Il Refresh Token viene immediatamente revocato nel database
     * - Il client dovrebbe eliminare entrambi i token dal localStorage/sessionStorage
     * 
     * REQUEST BODY (JSON):
     * {
     *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
     * }
     * 
     * RESPONSE (JSON):
     * {
     *   "success": true,
     *   "message": "Logout effettuato con successo",
     *   "data": null
     * }
     * 
     * @param request DTO contenente il refresh token da revocare
     * @return ResponseEntity con ApiResponseDTO di conferma
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDTO> logout(
            @Valid @RequestBody org.lessons.java.spec.bibliojwt.model.dto.RefreshTokenRequestDTO request
    ) {
        log.info("Richiesta logout");
        
        try {
            // Delega al service la revoca del refresh token
            userService.logout(request.getRefreshToken());
            
            log.info("Logout effettuato con successo");
            
            ApiResponseDTO response = new ApiResponseDTO(
                    true,
                    "Logout effettuato con successo. Il refresh token è stato revocato.",
                    null
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.warn("Logout fallito: {}", e.getMessage());
            throw e;  // Gestito da GlobalExceptionHandler
        }
    }
}
