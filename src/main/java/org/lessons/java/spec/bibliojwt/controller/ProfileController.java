package org.lessons.java.spec.bibliojwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.lessons.java.spec.bibliojwt.model.User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Controller per gestire la pagina del profilo utente.
 * 
 * Mostra le informazioni dell'utente autenticato in una pagina HTML.
 * Richiede autenticazione tramite form login o sessione.
 */
@Controller
@RequestMapping("/profile")
@Slf4j
public class ProfileController {

    /**
     * Mostra la pagina del profilo dell'utente autenticato.
     * 
     * Recupera automaticamente l'utente dal contesto di sicurezza
     * e passa i suoi dati alla vista per la visualizzazione.
     * 
     * @param user L'utente autenticato (iniettato da Spring Security)
     * @param model Il model per passare dati alla vista
     * @return Il nome della vista (profile.html)
     */
    @GetMapping
    public String showProfile(@AuthenticationPrincipal User user, Model model) {
        log.info("Accesso alla pagina profilo per utente: {}", user.getEmail());
        
        // Aggiungi i dati dell'utente al model
        model.addAttribute("user", user);
        model.addAttribute("fullName", user.getFirstName() + " " + user.getLastName());
        
        return "profile";
    }
}
