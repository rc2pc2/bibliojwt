package org.lessons.java.spec.bibliojwt.service;

import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("CustomUserDetailsService.loadUserByUsername chiamato con: {}", username);

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    logger.warn("❌ Utente NON trovato con email: {}", username);
                    return new UsernameNotFoundException("Utente non trovato con email: " + username);
                });

        logger.info("   Utente trovato: {} - Ruolo: {}", user.getEmail(), user.getRole());
        logger.debug("   Password hash salvata nel DB: {}", user.getPassword());
        logger.info("   Account abilitato: {}", user.isEnabled());
        logger.info("   Account non scaduto: {}", user.isAccountNonExpired());
        logger.info("   Account non bloccato: {}", user.isAccountNonLocked());
        logger.info("   Credenziali non scadute: {}", user.isCredentialsNonExpired());

        return user;
    }
}
