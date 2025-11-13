package org.lessons.java.spec.bibliojwt.controller;

import org.lessons.java.spec.bibliojwt.model.User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    @GetMapping
    public String dashboard(@AuthenticationPrincipal User user, Model model) {
        model.addAttribute("user", user);
        model.addAttribute("fullName", user.getFirstName() + " " + user.getLastName());
        return "dashboard";
    }
}
