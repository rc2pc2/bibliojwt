package org.lessons.java.spec.bibliojwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() { return "index"; }

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String logout,
                        Model model) {
        if (error != null) model.addAttribute("error", "Email o password non corretti");
        if (logout != null) model.addAttribute("message", "Logout effettuato con successo");
        return "login";
    }

    @GetMapping("/register")
    public String register() { return "register"; }
}
