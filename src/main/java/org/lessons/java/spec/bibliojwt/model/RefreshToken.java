package org.lessons.java.spec.bibliojwt.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Entità RefreshToken per gestire i token di aggiornamento JWT.
 * 
 * ARCHITETTURA:
 * - I Refresh Token sono memorizzati nel database per consentire revoca e rotazione
 * - Ogni utente può avere più refresh token attivi (diversi dispositivi)
 * - I token scaduti vengono automaticamente eliminati da un job schedulato
 * 
 * SICUREZZA:
 * - Token UUID v4 random (non prevedibili)
 * - Scadenza configurable (default 7 giorni)
 * - Campo 'revoked' per invalidazione manuale (logout, compromissione)
 * - Indici database per query veloci su token e userId
 * 
 * BEST PRACTICES:
 * - Token Rotation: ogni refresh genera un nuovo token e invalida il vecchio
 * - Single Use: un refresh token può essere usato una sola volta
 * - Device Tracking: opzionalmente può essere aggiunto deviceId/userAgent
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-1.5">RFC 6749 - Refresh Tokens</a>
 * @see <a href="https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/">Auth0 Refresh Token Guide</a>
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_token", columnList = "token"),
    @Index(name = "idx_user_id", columnList = "user_id")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Token UUID unico generato randomicamente.
     * NON è un JWT - è un semplice identificatore univoco.
     * Questo permette revoca istantanea senza dover gestire blacklist JWT.
     */
    @Column(nullable = false, unique = true, length = 36)
    private String token;

    /**
     * Riferimento all'utente proprietario del token.
     * Relazione ManyToOne: un utente può avere più refresh token
     * (uno per ogni dispositivo/sessione).
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * Data e ora di scadenza del token.
     * Dopo questa data il token non può più essere utilizzato.
     * Tipicamente impostato a 7 giorni dalla creazione.
     */
    @Column(nullable = false)
    private Instant expiryDate;

    /**
     * Flag per indicare se il token è stato revocato manualmente.
     * TRUE quando:
     * - L'utente fa logout
     * - L'utente cambia password (tutti i token vengono revocati)
     * - Il token viene riutilizzato (possibile attacco - revoca tutti i token dell'utente)
     * - L'amministratore revoca la sessione
     */
    @Column(nullable = false)
    private boolean revoked = false;

    /**
     * Timestamp di creazione del token.
     * Utile per audit e statistiche.
     */
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Opzionale: User Agent del browser/app che ha richiesto il token.
     * Utile per identificare sessioni sospette.
     */
    @Column(length = 500)
    private String userAgent;

    /**
     * Opzionale: Indirizzo IP da cui è stato richiesto il token.
     * Utile per rilevare accessi anomali.
     */
    @Column(length = 45) // IPv6 max length
    private String ipAddress;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
    }

    // Constructors

    public RefreshToken() {
    }

    public RefreshToken(String token, User user, Instant expiryDate) {
        this.token = token;
        this.user = user;
        this.expiryDate = expiryDate;
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    /**
     * Verifica se il token è scaduto.
     * 
     * @return true se la data di scadenza è passata, false altrimenti
     */
    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }

    /**
     * Verifica se il token è valido (non scaduto e non revocato).
     * 
     * @return true se il token può essere utilizzato, false altrimenti
     */
    public boolean isValid() {
        return !isExpired() && !isRevoked();
    }

    @Override
    public String toString() {
        return "RefreshToken{" +
                "id=" + id +
                ", token='" + token + '\'' +
                ", userId=" + (user != null ? user.getId() : null) +
                ", expiryDate=" + expiryDate +
                ", revoked=" + revoked +
                ", createdAt=" + createdAt +
                '}';
    }
}
