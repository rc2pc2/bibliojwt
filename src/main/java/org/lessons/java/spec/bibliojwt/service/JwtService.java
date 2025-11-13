package org.lessons.java.spec.bibliojwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    /**
     * Chiave segreta codificata in Base64; il valore è preso da
     * application.properties tramite la property {@code jwt.secret}.
     * Viene usata per firmare e verificare i token JWT.
     */
    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * Durata in millisecondi del token (time-to-live). Prelevata dalla
     * property {@code jwt.expiration} (es. 3600000 = 1 ora).
     */
    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    /**
     * Genera un token JWT per l'utente fornito. Nel token viene inserita
     * una claim custom "role" che rappresenta la prima authority presente
     * nelle authorities dell'utente (semplice scelta di esempio).
     *
     * @param userDetails i dettagli dell'utente (username e authorities)
     * @return token JWT firmato come String
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        // Estrae la prima authority e la mette nella claim "role". Attenzione:
        // qui si assume che almeno una authority sia presente (usando get()).
        claims.put("role", userDetails.getAuthorities().stream().findFirst().get().getAuthority());
        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Costruisce materialmente il token JWT con claims, subject, issuedAt,
     * expiration e firma.
     *
     * @param claims mappa di claims da inserire nel payload del token
     * @param subject il soggetto del token (di solito lo username/email)
     * @return token JWT compatto (String)
     */
    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Estrae lo username (subject) dal token JWT.
     *
     * @param token il JWT
     * @return il subject (username/email) contenuto nel token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Estrae la data di scadenza dal token JWT.
     *
     * @param token il JWT
     * @return data di expiration
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Legge la claim custom "role" dal token e la ritorna come String.
     *
     * @param token il JWT
     * @return valore della claim "role"
     */
    public String extractRole(String token) {
        final Claims claims = extractAllClaims(token);
        return claims.get("role", String.class);
    }

    /**
     * Estrae una claim usando una funzione di mapping sulle Claims.
     * Permette di riusare la logica di parsing una sola volta.
     *
     * @param token il JWT
     * @param claimsResolver funzione che estrae la specifica informazione dalle Claims
     * @param <T> tipo del valore estratto
     * @return valore estratto
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Effettua il parsing completo del token e ritorna tutte le Claims.
     * Usa il parser della libreria jjwt impostato per verificare la firma
     * con la chiave restituita da {@link #getSigningKey()}.
     *
     * @param token il JWT firmato
     * @return oggetto Claims contenente tutte le claim del token
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifica se il token è già scaduto confrontando la claim expiration
     * con la data corrente.
     *
     * @param token il JWT
     * @return true se il token è scaduto, false altrimenti
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Valida il token confrontando lo username contenuto nel token con
     * quello del {@code UserDetails} fornito e verificando che il token
     * non sia scaduto.
     *
     * @param token il JWT
     * @param userDetails i dettagli dell'utente attesi
     * @return true se il token è valido per l'utente, false altrimenti
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * Converte la {@code secretKey} Base64 in byte[] e crea una SecretKey
     * HMAC-SHA usando le utility di jjwt.
     *
     * @return SecretKey usata per firmare e verificare i token
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
