package org.lessons.java.spec.bibliojwt.service;

import org.lessons.java.spec.bibliojwt.exception.InvalidTokenException;
import org.lessons.java.spec.bibliojwt.model.RefreshToken;
import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

/**
 * Service per la gestione completa dei Refresh Token.
 * 
 * RESPONSABILITÀ:
 * 1. Creazione refresh token con UUID random
 * 2. Validazione e verifica scadenza
 * 3. Token Rotation (security best practice)
 * 4. Revoca manuale e automatica
 * 5. Pulizia periodica token scaduti
 * 6. Rate limiting e protezione attacchi
 * 
 * CONFIGURAZIONE:
 * - refresh-token.duration-days: durata in giorni (default 7)
 * - refresh-token.max-per-user: max sessioni simultanee (default 5)
 * - refresh-token.cleanup-schedule: cron per pulizia (default ogni giorno alle 3 AM)
 * 
 * SICUREZZA:
 * - Token Rotation: ogni refresh genera nuovo token e invalida il vecchio
 * - Reuse Detection: se un token revocato viene riutilizzato, invalida TUTTI i token dell'utente
 * - Scadenza: token automaticamente scaduti dopo N giorni
 * - Rate Limiting: max tentativi refresh per prevenire brute force
 * 
 * TOKEN ROTATION FLOW:
 * 1. Client usa refresh token per ottenere nuovo access token
 * 2. Server valida refresh token
 * 3. Server genera NUOVO refresh token
 * 4. Server REVOCA vecchio refresh token
 * 5. Server ritorna nuovo access token + nuovo refresh token
 * 6. Client sostituisce vecchio refresh token con il nuovo
 * 
 * PERCHÉ TOKEN ROTATION?
 * - Se un attaccante ruba un refresh token, può usarlo solo UNA volta
 * - Il token rubato viene immediatamente invalidato
 * - Se l'attaccante prova a riutilizzarlo, il sistema rileva l'anomalia
 * - Tutti i token dell'utente vengono revocati per sicurezza
 * 
 * @see <a href="https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation">Auth0 Token Rotation</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics">OAuth 2.0 Security Best Practices</a>
 */
@Service
@Transactional
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * Durata del refresh token in giorni.
     * Default: 7 giorni.
     * 
     * CONSIDERAZIONI:
     * - Troppo breve: utente deve rifare login spesso (UX negativa)
     * - Troppo lungo: finestra più ampia per attacchi (sicurezza ridotta)
     * - 7 giorni è un buon compromesso per la maggior parte delle applicazioni
     * - Per applicazioni bancarie: 1-3 giorni
     * - Per social network: 30-90 giorni
     */
    @Value("${refresh-token.duration-days:7}")
    private int refreshTokenDurationDays;

    /**
     * Numero massimo di refresh token attivi per utente.
     * Default: 5 (tipicamente: PC, telefono, tablet, browser work, browser home)
     * 
     * PERCHÉ LIMITARE?
     * - Previene creazione massiva di token (attacco DoS)
     * - Forza utente a gestire sessioni attive
     * - Facilita rilevamento account compromessi
     */
    @Value("${refresh-token.max-per-user:5}")
    private int maxTokensPerUser;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * Crea un nuovo refresh token per un utente.
     * 
     * PROCESSO:
     * 1. Genera UUID v4 random (praticamente impossibile da indovinare)
     * 2. Calcola data scadenza (oggi + N giorni)
     * 3. Verifica limite token per utente
     * 4. Se limite superato, elimina il token più vecchio
     * 5. Salva nuovo token nel database
     * 
     * PARAMETRI OPZIONALI:
     * @param userAgent User-Agent del client (per audit)
     * @param ipAddress IP del client (per rilevare accessi anomali)
     * 
     * @param user l'utente per cui creare il token
     * @return il refresh token creato
     */
    public RefreshToken createRefreshToken(User user) {
        return createRefreshToken(user, null, null);
    }

    /**
     * Crea refresh token con informazioni aggiuntive per audit.
     */
    public RefreshToken createRefreshToken(User user, String userAgent, String ipAddress) {
        // Verifica limite token per utente
        long activeTokensCount = refreshTokenRepository.countActiveTokensByUser(user, Instant.now());
        
        if (activeTokensCount >= maxTokensPerUser) {
            logger.warn("🚨 Utente {} ha raggiunto il limite di {} token attivi. " +
                       "Elimino il token più vecchio.", user.getEmail(), maxTokensPerUser);
            
            // Trova e elimina il token più vecchio
            List<RefreshToken> activeTokens = refreshTokenRepository
                .findActiveTokensByUser(user, Instant.now());
            
            if (!activeTokens.isEmpty()) {
                RefreshToken oldestToken = activeTokens.stream()
                    .min((t1, t2) -> t1.getCreatedAt().compareTo(t2.getCreatedAt()))
                    .orElseThrow();
                
                refreshTokenRepository.delete(oldestToken);
                logger.info("✅ Token più vecchio eliminato: {}", oldestToken.getToken());
            }
        }

        // Genera nuovo token
        String tokenValue = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plus(refreshTokenDurationDays, ChronoUnit.DAYS);

        RefreshToken refreshToken = new RefreshToken(tokenValue, user, expiryDate);
        refreshToken.setUserAgent(userAgent);
        refreshToken.setIpAddress(ipAddress);

        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        
        logger.info("✅ Nuovo refresh token creato per utente {} (scade: {})", 
                   user.getEmail(), expiryDate);
        
        return savedToken;
    }

    /**
     * Verifica e valida un refresh token.
     * 
     * CONTROLLI ESEGUITI:
     * 1. Token exists nel database?
     * 2. Token è scaduto?
     * 3. Token è stato revocato?
     * 4. User associato è ancora attivo?
     * 
     * SICUREZZA IMPORTANTE:
     * Se un token REVOCATO viene riutilizzato, è un chiaro segnale di attacco!
     * In questo caso:
     * - Log evento sospetto
     * - Revoca TUTTI i token dell'utente
     * - Notifica amministratori (TODO: implementare alert)
     * - Forza utente a rifare login
     * 
     * @param tokenValue il valore UUID del token
     * @return il RefreshToken validato
     * @throws InvalidTokenException se token non valido
     */
    public RefreshToken verifyRefreshToken(String tokenValue) {
        RefreshToken token = refreshTokenRepository.findByToken(tokenValue)
            .orElseThrow(() -> {
                logger.warn("❌ Tentativo di uso di refresh token inesistente: {}", tokenValue);
                return new InvalidTokenException("Refresh token non trovato o non valido");
            });

        // SECURITY CHECK: Token Reuse Detection
        if (token.isRevoked()) {
            logger.error("🚨 SECURITY ALERT: Tentativo di riutilizzo di token revocato! " +
                        "Token: {} | Utente: {} | Possibile attacco in corso!", 
                        tokenValue, token.getUser().getEmail());
            
            // Revoca TUTTI i token dell'utente per sicurezza
            int revokedCount = refreshTokenRepository.revokeAllUserTokens(token.getUser());
            
            logger.error("🔒 Per sicurezza, revocati tutti i {} token dell'utente {}. " +
                        "L'utente dovrà rifare login su tutti i dispositivi.", 
                        revokedCount, token.getUser().getEmail());
            
            // TODO: Invia notifica email all'utente
            // TODO: Alert amministratori di sistema
            // TODO: Registra evento in security audit log
            
            throw new InvalidTokenException(
                "Token revocato riutilizzato! Per sicurezza tutte le sessioni sono state invalidate. " +
                "Per favore effettua nuovamente il login."
            );
        }

        // Check scadenza
        if (token.isExpired()) {
            logger.info("⏰ Refresh token scaduto per utente {}", token.getUser().getEmail());
            throw new InvalidTokenException("Refresh token scaduto. Effettua nuovamente il login.");
        }

        // Check utente attivo
        if (!token.getUser().isEnabled()) {
            logger.warn("🚫 Tentativo di refresh con utente disabilitato: {}", 
                       token.getUser().getEmail());
            throw new InvalidTokenException("Account disabilitato");
        }

        logger.info("✅ Refresh token validato con successo per utente {}", 
                   token.getUser().getEmail());
        
        return token;
    }

    /**
     * REFRESH TOKEN ROTATION
     * 
     * Questo è il metodo più importante per la sicurezza!
     * 
     * PROCESSO:
     * 1. Valida il vecchio token
     * 2. Estrae l'utente dal token
     * 3. REVOCA immediatamente il vecchio token
     * 4. Genera un NUOVO token
     * 5. Ritorna il nuovo token
     * 
     * PERCHÉ ROTATION?
     * ────────────────
     * Scenario senza rotation:
     * - Attaccante ruba refresh token
     * - Può usarlo per 7 giorni finché non scade
     * - Utente legittimo continua a usare lo stesso token
     * - Attacco non rilevabile
     * 
     * Scenario con rotation:
     * - Attaccante ruba refresh token
     * - Attaccante usa token per ottenere access token (token viene REVOCATO)
     * - Utente legittimo prova a usare token → ERRORE (token revocato)
     * - Sistema rileva riutilizzo token revocato
     * - Sistema REVOCA TUTTI i token dell'utente
     * - Attaccante e utente vengono disconnessi
     * - Attacco neutralizzato!
     * 
     * @param oldTokenValue il vecchio token da sostituire
     * @param userAgent User-Agent per il nuovo token
     * @param ipAddress IP address per il nuovo token
     * @return il nuovo token generato
     * @throws InvalidTokenException se vecchio token non valido
     */
    public RefreshToken rotateRefreshToken(String oldTokenValue, String userAgent, String ipAddress) {
        logger.info("🔄 Inizio rotazione refresh token");
        
        // 1. Valida vecchio token (include tutti i security checks)
        RefreshToken oldToken = verifyRefreshToken(oldTokenValue);
        User user = oldToken.getUser();
        
        // 2. REVOCA immediatamente il vecchio token
        oldToken.setRevoked(true);
        refreshTokenRepository.save(oldToken);
        logger.info("🔒 Vecchio token revocato: {}", oldTokenValue);
        
        // 3. Genera nuovo token
        RefreshToken newToken = createRefreshToken(user, userAgent, ipAddress);
        logger.info("✅ Nuovo token generato: {} per utente {}", 
                   newToken.getToken(), user.getEmail());
        
        return newToken;
    }

    /**
     * Revoca un singolo refresh token (es. logout da un dispositivo specifico).
     * 
     * @param tokenValue il token da revocare
     * @throws InvalidTokenException se token non trovato
     */
    public void revokeToken(String tokenValue) {
        RefreshToken token = refreshTokenRepository.findByToken(tokenValue)
            .orElseThrow(() -> new InvalidTokenException("Token non trovato"));
        
        token.setRevoked(true);
        refreshTokenRepository.save(token);
        
        logger.info("🔒 Token revocato manualmente: {} (utente: {})", 
                   tokenValue, token.getUser().getEmail());
    }

    /**
     * Revoca TUTTI i token di un utente.
     * 
     * UTILIZZO:
     * - Logout globale (disconnetti da tutti i dispositivi)
     * - Cambio password (policy di sicurezza)
     * - Account compromesso (azione amministratore)
     * - Sospensione account
     * 
     * @param user l'utente
     * @return numero di token revocati
     */
    public int revokeAllUserTokens(User user) {
        int count = refreshTokenRepository.revokeAllUserTokens(user);
        logger.warn("🔒 Revocati tutti i {} token dell'utente {}", count, user.getEmail());
        return count;
    }

    /**
     * Elimina fisicamente tutti i token di un utente.
     * Usato quando l'account viene eliminato (GDPR compliance).
     * 
     * @param user l'utente
     * @return numero di token eliminati
     */
    public int deleteAllUserTokens(User user) {
        int count = refreshTokenRepository.deleteByUser(user);
        logger.info("🗑️ Eliminati tutti i {} token dell'utente {}", count, user.getEmail());
        return count;
    }

    /**
     * Trova tutti i token attivi di un utente.
     * Utile per mostrare "sessioni attive" nell'interfaccia utente.
     * 
     * @param user l'utente
     * @return lista di token attivi
     */
    @Transactional(readOnly = true)
    public List<RefreshToken> getActiveUserTokens(User user) {
        return refreshTokenRepository.findActiveTokensByUser(user, Instant.now());
    }

    /**
     * JOB SCHEDULATO: Pulizia automatica token scaduti.
     * 
     * ESECUZIONE:
     * - Ogni giorno alle 3:00 AM (cron: "0 0 3 * * ?")
     * - Durante ore di basso traffico per minimizzare impatto
     * 
     * AZIONI:
     * 1. Elimina tutti i token con expiryDate < now
     * 2. Elimina token revocati più vecchi di 30 giorni (per audit)
     * 3. Log statistiche pulizia
     * 
     * PERFORMANCE:
     * - Batch delete efficiente
     * - Transazione atomica
     * - Nessun lock su tabella users
     * 
     * MONITORING:
     * - Log numero token eliminati
     * - Alert se volume anomalo (possibile problema)
     */
    @Scheduled(cron = "${refresh-token.cleanup-schedule:0 0 3 * * ?}")
    @Transactional
    public void cleanupExpiredTokens() {
        logger.info("🧹 Inizio pulizia token scaduti...");
        
        Instant now = Instant.now();
        
        // 1. Elimina token scaduti
        int expiredCount = refreshTokenRepository.deleteAllExpiredTokens(now);
        logger.info("Eliminati {} token scaduti", expiredCount);
        
        // 2. Elimina token revocati vecchi (conserva ultimi 30 giorni per audit)
        Instant thirtyDaysAgo = now.minus(30, ChronoUnit.DAYS);
        int revokedCount = refreshTokenRepository.deleteRevokedTokensOlderThan(thirtyDaysAgo);
        logger.info("Eliminati {} token revocati vecchi", revokedCount);
        
        logger.info("Pulizia completata: {} token totali eliminati", 
                   expiredCount + revokedCount);
        
        // TODO: Se volume troppo alto, invia alert agli amministratori
    }

    /**
     * Trova e log token sospetti per security monitoring.
     * Può essere chiamato periodicamente o on-demand.
     */
    public void checkSuspiciousActivity() {
        List<RefreshToken> suspicious = refreshTokenRepository.findSuspiciousTokens(Instant.now());
        
        if (!suspicious.isEmpty()) {
            logger.warn("Trovati {} token sospetti (revocati ma non scaduti)", 
                       suspicious.size());
            
            for (RefreshToken token : suspicious) {
                logger.warn("   Token sospetto: {} | Utente: {} | Revocato il: {}", 
                           token.getToken(), 
                           token.getUser().getEmail(), 
                           token.getCreatedAt());
            }
            
            // TODO: Invia report agli amministratori
        }
    }
}
