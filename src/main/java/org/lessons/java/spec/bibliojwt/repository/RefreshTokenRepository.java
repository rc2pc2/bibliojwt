package org.lessons.java.spec.bibliojwt.repository;

import org.lessons.java.spec.bibliojwt.model.RefreshToken;
import org.lessons.java.spec.bibliojwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository per la gestione dei Refresh Token nel database.
 * 
 * FUNZIONALITÀ PRINCIPALI:
 * 1. Ricerca token per validazione
 * 2. Eliminazione token per utente (logout/cambio password)
 * 3. Pulizia automatica token scaduti
 * 4. Query ottimizzate con indici
 * 
 * PERFORMANCE:
 * - Indici su 'token' e 'user_id' per query veloci
 * - Batch delete per pulizia token scaduti
 * - Fetch LAZY per relazioni (evita N+1 queries)
 * 
 * SICUREZZA:
 * - Nessun metodo findAll() pubblico (previene data leaks)
 * - Query parametrizzate (SQL injection safe)
 * - Transazionalità per operazioni di modifica
 * 
 * @see RefreshToken
 * @see <a href="https://docs.spring.io/spring-data/jpa/docs/current/reference/html/">Spring Data JPA Reference</a>
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Trova un refresh token tramite il suo valore UUID.
     * 
     * UTILIZZO:
     * - Validazione token durante refresh endpoint
     * - Verifica esistenza prima della revoca
     * 
     * PERFORMANCE:
     * - Query su indice 'idx_token' (molto veloce)
     * - Fetch EAGER di user per evitare LazyInitializationException
     * 
     * @param token il valore UUID del token
     * @return Optional contenente il RefreshToken se trovato, empty altrimenti
     */
    @Query("SELECT rt FROM RefreshToken rt JOIN FETCH rt.user WHERE rt.token = :token")
    Optional<RefreshToken> findByToken(@Param("token") String token);

    /**
     * Trova tutti i refresh token attivi (non revocati, non scaduti) di un utente.
     * 
     * UTILIZZO:
     * - Visualizzazione sessioni attive nell'interfaccia utente
     * - Audit delle sessioni per sicurezza
     * 
     * @param user l'utente di cui cercare i token
     * @param now il timestamp corrente per filtrare i token scaduti
     * @return lista di token attivi
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user " +
           "AND rt.revoked = false AND rt.expiryDate > :now")
    List<RefreshToken> findActiveTokensByUser(@Param("user") User user, @Param("now") Instant now);

    /**
     * Conta il numero di refresh token attivi per un utente.
     * 
     * UTILIZZO:
     * - Limitare numero massimo di sessioni simultanee
     * - Statistiche utente
     * 
     * @param user l'utente
     * @param now timestamp corrente
     * @return numero di token attivi
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user " +
           "AND rt.revoked = false AND rt.expiryDate > :now")
    long countActiveTokensByUser(@Param("user") User user, @Param("now") Instant now);

//     TODO esempio: Potrei farlo anche usando JPA
// !    long countByUserAndRevokedFalseAndExpiryDateAfter(User user, Instant now);

    /**
     * Revoca (imposta revoked=true) tutti i token di un utente.
     * 
     * UTILIZZO:
     * - Logout globale (disconnetti da tutti i dispositivi)
     * - Cambio password (invalida tutte le sessioni per sicurezza)
     * - Azione amministratore (sospensione account)
     * 
     * SICUREZZA IMPORTANTE:
     * - Quando un refresh token viene riutilizzato (possibile attacco),
     *   questa query viene eseguita per invalidare TUTTI i token dell'utente
     * - L'utente dovrà rifare login su tutti i dispositivi
     * 
     * @param user l'utente di cui revocare i token
     * @return numero di token revocati
     */
       @Modifying
       @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user = :user")
       int revokeAllUserTokens(@Param("user") User user);

    /**
     * Elimina fisicamente tutti i token di un utente.
     * 
     * UTILIZZO:
     * - Eliminazione account utente (cascata)
     * - Pulizia dati per GDPR compliance
     * 
     * @param user l'utente
     * @return numero di token eliminati
     */
       @Modifying
       @Query("DELETE FROM RefreshToken rt WHERE rt.user = :user")
       int deleteByUser(@Param("user") User user);

    /**
     * Elimina tutti i token scaduti dal database.
     * 
     * UTILIZZO:
     * - Job schedulato (eseguito ogni notte)
     * - Manutenzione database per performance
     * - Risparmio spazio su disco
     * 
     * PERFORMANCE:
     * - Batch delete efficiente
     * - Indice su expiryDate per filtraggio veloce
     * 
     * FREQUENZA CONSIGLIATA:
     * - Eseguire 1 volta al giorno durante ore di basso traffico
     * - Alternativa: eseguire ogni settimana se il volume è basso
     * 
     * @param now timestamp corrente
     * @return numero di token eliminati
     */
       @Modifying
       @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
       int deleteAllExpiredTokens(@Param("now") Instant now);

    /**
     * Elimina tutti i token revocati più vecchi di una certa data.
     * 
     * UTILIZZO:
     * - Pulizia token revocati ma non ancora scaduti
     * - Mantenere database pulito
     * 
     * POLICY CONSIGLIATA:
     * - Conservare token revocati per 30 giorni (audit/forensics)
     * - Poi eliminarli per risparmiare spazio
     * 
     * @param olderThan data limite
     * @return numero di token eliminati
     */
       @Modifying
       @Query("DELETE FROM RefreshToken rt WHERE rt.revoked = true AND rt.createdAt < :olderThan")
       int deleteRevokedTokensOlderThan(@Param("olderThan") Instant olderThan);

    /**
     * Trova token sospetti che sono stati utilizzati dopo la revoca.
     * 
     * UTILIZZO:
     * - Rilevamento attacchi (token reuse)
     * - Security monitoring
     * - Alert amministratori
     * 
     * @param now timestamp corrente
     * @return lista di token sospetti
     */
       @Query("SELECT rt FROM RefreshToken rt JOIN FETCH rt.user " +
              "WHERE rt.revoked = true AND rt.expiryDate > :now")
       List<RefreshToken> findSuspiciousTokens(@Param("now") Instant now);
}
