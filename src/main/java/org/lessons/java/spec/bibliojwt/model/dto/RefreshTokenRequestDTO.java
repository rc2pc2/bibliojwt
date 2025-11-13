package org.lessons.java.spec.bibliojwt.model.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO per la richiesta di refresh del token JWT.
 * 
 * UTILIZZO:
 * Quando l'access token scade, il client invia questo DTO all'endpoint /api/auth/refresh
 * per ottenere un nuovo access token senza dover rifare il login.
 * 
 * FLUSSO:
 * 1. Client rileva che l'access token è scaduto (401 Unauthorized)
 * 2. Client invia POST /api/auth/refresh con il refresh token
 * 3. Server valida il refresh token
 * 4. Server genera nuovo access token + nuovo refresh token (rotation)
 * 5. Server ritorna AuthResponseDTO con i nuovi token
 * 6. Client aggiorna i suoi token salvati
 * 
 * SICUREZZA:
 * - Il refresh token NON deve MAI essere esposto nel browser
 * - Deve essere salvato in modo sicuro (es. HttpOnly cookie o secure storage)
 * - Ogni refresh token può essere usato UNA SOLA VOLTA (token rotation)
 * 
 * ESEMPIO JSON:
 * {
 *   "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
 * }
 * 
 * @see AuthResponseDTO
 * @see org.lessons.java.spec.bibliojwt.restcontroller.AuthRestController#refreshToken
 */
public class RefreshTokenRequestDTO {

    /**
     * Il refresh token UUID generato durante il login.
     * 
     * VALIDAZIONE:
     * - Non può essere null
     * - Non può essere vuoto
     * - Deve essere un UUID valido (formato: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
     * 
     * NOTA: La validazione del formato UUID viene fatta nel service,
     * non qui, per fornire messaggi di errore più specifici.
     */
    @NotBlank(message = "Refresh token è obbligatorio")
    private String refreshToken;

    // Constructors

    public RefreshTokenRequestDTO() {
    }

    public RefreshTokenRequestDTO(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    // Getters and Setters

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public String toString() {
        // NON loggare il token completo per sicurezza!
        // Mostra solo i primi e ultimi 4 caratteri
        String masked = refreshToken != null && refreshToken.length() > 8
            ? refreshToken.substring(0, 4) + "****" + refreshToken.substring(refreshToken.length() - 4)
            : "****";
        
        return "RefreshTokenRequestDTO{refreshToken='" + masked + "'}";
    }
}
