package org.lessons.java.spec.bibliojwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * Configurazione principale di Spring Security.
 * 
 * Implementa DUE meccanismi di autenticazione:
 * 1. JWT per API REST (/api/**) - Stateless
 * 2. Form-based per pagine web (/**) - Stateful con sessioni
 * 
 * Questa è una configurazione DIDATTICA che mostra entrambi gli approcci.
 * In produzione, tipicamente si usa solo uno dei due.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final JwtAuthenticationEntryPoint jwtAuthEntryPoint;
    private final org.lessons.java.spec.bibliojwt.service.CustomUserDetailsService userDetailsService;
    
    /**
     * SECURITY FILTER CHAIN #1: Per API REST con JWT
     * 
     * Order(1) = alta priorità, viene valutato per primo
     * 
     * Caratteristiche:
     * - Stateless: nessuna sessione creata, ogni richiesta è indipendente
     * - CSRF disabilitato: JWT non usa cookie, quindi non è vulnerabile a CSRF
     * - CORS abilitato: permette richieste cross-origin da frontend separati
     * - JWT filter: aggiunto alla catena per validare token ad ogni richiesta
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            .csrf(csrf -> csrf.disable())
            
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            .authorizeHttpRequests(auth -> auth
                // Endpoint pubblici di autenticazione (non richiedono JWT)
                .requestMatchers("/api/auth/login", "/api/auth/register", "/api/auth/refresh", "/api/auth/logout").permitAll()
                // Endpoint protetti con ruoli specifici
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/moderator/**").hasAnyRole("MODERATOR", "ADMIN")
                // Tutti gli altri endpoint API richiedono autenticazione
                .requestMatchers("/api/**").authenticated()
            )
            
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(jwtAuthEntryPoint)
            )
            
            .authenticationProvider(authenticationProvider())
            
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    /**
     * SECURITY FILTER CHAIN #2: Per Pagine Web con Form Login
     * 
     * Order(2) = priorità più bassa, valutato dopo il primo
     * 
     * Caratteristiche:
     * - Stateful: usa sessioni salvate nel server
     * - CSRF abilitato: protegge i form da attacchi CSRF
     * - Form login: pagina di login personalizzata
     * - Remember-me: opzione per rimanere loggati
     */
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/h2-console/**")
            )
            
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
            )
            
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/register", "/css/**", "/js/**", "/h2-console/**").permitAll()
                .requestMatchers("/profile/**").authenticated()
                .requestMatchers("/dashboard/**").authenticated()
                .requestMatchers("/admin/**").hasRole("ADMIN")
            )
            
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/profile", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            
            .rememberMe(remember -> remember
                .key("uniqueAndSecretKey")
                .tokenValiditySeconds(86400)
                .userDetailsService(userDetailsService)
            )
            
            .headers(headers -> headers
                .frameOptions(frame -> frame.sameOrigin())
            );
        
        return http.build();
    }
    
    /**
     * Configurazione CORS per permettere richieste cross-origin.
     * Fondamentale quando frontend e backend sono su domini/porte diverse.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",
            "http://localhost:4200",
            "http://localhost:8081"
        ));
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setExposedHeaders(Arrays.asList("Authorization"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    /**
     * Password encoder questa volta ho scelto BCRYPT.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    /**
     * Provider che usa UserDetailsService per caricare utenti
     * e PasswordEncoder per verificare le password.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }
    
    /**
     * Authentication Manager usato per validare credenziali di login.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * UserDetailsService personalizzato per caricare utenti dal database.
     */
    // CustomUserDetailsService is a @Service bean and is injected

}
