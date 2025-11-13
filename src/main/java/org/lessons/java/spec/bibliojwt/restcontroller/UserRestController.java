package org.lessons.java.spec.bibliojwt.restcontroller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.model.dto.ApiResponseDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * REST Controller per gestire le operazioni del profilo utente.
 * Accessibile a tutti gli utenti autenticati.
 * 
 * PATH BASE: /api/user
 * 
 * ENDPOINT DISPONIBILI:
 * - GET /api/user/profile - Ottiene i dati del profilo dell'utente loggato
 */
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
public class UserRestController {

    /**
     * Endpoint per ottenere il profilo dell'utente autenticato.
     * 
     * Usa @AuthenticationPrincipal per ottenere automaticamente
     * l'utente dal contesto di sicurezza di Spring Security.
     * 
     * AUTENTICAZIONE RICHIESTA: Sì (JWT Token o Session)
     * RUOLI AUTORIZZATI: Tutti gli utenti autenticati
     * 
     * ESEMPIO RICHIESTA:
     * GET http://localhost:8080/api/user/profile
     * Headers: Authorization: Bearer <jwt-token>
     * 
     * ESEMPIO RISPOSTA (200 OK):
     * {
     *   "success": true,
     *   "message": "Profilo recuperato con successo",
     *   "data": {
     *     "id": 1,
     *     "email": "admin@univ.it",
     *     "firstName": "Anita",
     *     "lastName": "Garibaldi",
     *     "fullName": "Anita Garibaldi",
     *     "role": "ROLE_ADMIN",
     *     "enabled": true
     *   }
     * }
     * 
     * @param user L'utente autenticato (iniettato automaticamente da Spring Security)
     * @return ResponseEntity con ApiResponseDTO contenente i dati del profilo
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponseDTO> getProfile(@AuthenticationPrincipal User user) {
        log.info("Recupero profilo per utente: {}", user.getEmail());
        
        Map<String, Object> profileData = new HashMap<>();
        profileData.put("id", user.getId());
        profileData.put("email", user.getEmail());
        profileData.put("firstName", user.getFirstName());
        profileData.put("lastName", user.getLastName());
        profileData.put("fullName", user.getFirstName() + " " + user.getLastName());
        profileData.put("role", user.getRole());
        profileData.put("enabled", user.isEnabled());
        
        ApiResponseDTO response = new ApiResponseDTO(
            true, 
            "Profilo recuperato con successo", 
            profileData
        );
        
        log.info("Profilo recuperato con successo per: {}", user.getEmail());
        return ResponseEntity.ok(response);
    }
}
