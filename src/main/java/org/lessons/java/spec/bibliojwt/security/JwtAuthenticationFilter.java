package org.lessons.java.spec.bibliojwt.security;

import org.lessons.java.spec.bibliojwt.service.CustomUserDetailsService;
import org.lessons.java.spec.bibliojwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
/**
 * Filtro Spring che intercetta ogni richiesta HTTP (una sola volta per richiesta)
 * e tenta di autenticare l'utente sulla base di un token JWT presente
 * nell'header HTTP "Authorization" con schema Bearer.
 *
 * Funzioni principali:
 * - estrae il token JWT dall'header Authorization
 * - estrae l'username (qui chiamato userEmail) dal token
 * - carica i dettagli dell'utente dal repository tramite
 *   {@link org.lessons.java.spec.bibliojwt.service.CustomUserDetailsService}
 * - valida il token con {@link org.lessons.java.spec.bibliojwt.service.JwtService}
 * - se il token è valido, crea un'istanza di
 *   {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken}
 *   e la imposta nel {@link org.springframework.security.core.context.SecurityContextHolder}
 *
 * Alcune richieste sono escluse dal filtro (es. endpoint di autenticazione,
 * risorse statiche e la console H2) tramite l'override di
 * {@link #shouldNotFilter(javax.servlet.http.HttpServletRequest)}.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * Servizio che incapsula la logica legata ai JWT: parsing, estrazione claims
     * (es. username/email) e validazione (firma, scadenza, ecc.).
     */
    private final JwtService jwtService;

    /**
     * Servizio custom per caricare i dettagli dell'utente (implementa
     * {@code UserDetailsService}) dato uno username/email. Viene usato per
     * ottenere le authorities e verificare che l'utente esista ancora.
     */
    private final CustomUserDetailsService userDetailsService;

    /**
     * Costruttore con dependency injection via constructor — Spring inietterà
     * le implementazioni di {@code JwtService} e
     * {@code CustomUserDetailsService}. L'iniezione via costruttore favorisce
     * l'immutabilità dei campi e la testabilità.
     *
     * @param jwtService servizio per operazioni sui token JWT
     * @param userDetailsService servizio per caricare i dettagli utente
     */
    public JwtAuthenticationFilter(JwtService jwtService, CustomUserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /**
         * Metodo principale del filtro. Per ogni richiesta:
         * 1. legge l'header "Authorization"
         * 2. se l'header non è presente o non è del tipo Bearer, delega e termina
         * 3. estrae il token rimuovendo il prefisso "Bearer "
         * 4. estrae lo username/email dal token
         * 5. se l'utente non è già autenticato nel SecurityContext e l'username
         *    è presente, carica i dettagli dell'utente e valida il token
         * 6. se il token è valido, costruisce l'Authentication e la imposta
         *    nel SecurityContext
         * 7. in ogni caso prosegue la catena di filtri
         *
         * Nota: gli errori durante parsing/validazione del token vengono loggati
         * ma non provocano una risposta 401 direttamente qui; la gestione
         * finale dell'accesso è demandata alla configurazione di Spring
         * Security a valle.
         */

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Se non esiste header Authorization o non è nel formato "Bearer <token>",
        // non proviamo ad autenticare e proseguiamo la catena.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Rimuove il prefisso "Bearer " per ottenere il token puro
        jwt = authHeader.substring(7);

        try {
            // Estrae l'username (qui usato come email) dalle claims del JWT
            userEmail = jwtService.extractUsername(jwt);

            // Se abbiamo un username e non c'è già un'Authentication impostata,
            // proviamo a caricare i dettagli dell'utente e validare il token.
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
                // La validazione può includere firma, scadenza e verifica che il
                // token corrisponda all'utente caricato.
                if (jwtService.validateToken(jwt, userDetails)) {
                    // Crea un Authentication privo di credenziali (null) dato che
                    // l'autenticazione è basata su token, non su password.
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    // Aggiunge dettagli web (es. remoteAddress, sessionId) all'authToken
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // Imposta l'autenticazione nel contesto di sicurezza di Spring
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // Errori durante parsing/validazione vengono loggati. Non interrompiamo
            // immediatamente la request: la decisione finale spetta alle regole
            // di sicurezza a valle.
            logger.error("Cannot set user authentication: " + e.getMessage());
        }

        // Prosegue la catena di filtri in ogni caso
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        /**
         * Esclude dall'esecuzione del filtro le richieste verso percorsi che non
         * richiedono controllo JWT, come gli endpoint di autenticazione
         * (es. `/api/auth/`), la console H2 e le risorse statiche (/css, /js).
         * Restituendo true qui, {@code doFilterInternal} non verrà eseguito.
         */
        String path = request.getRequestURI();
        return path.startsWith("/api/auth/") || path.startsWith("/h2-console") || path.startsWith("/css/") || path.startsWith("/js/");
    }
}
