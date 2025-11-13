package org.lessons.java.spec.bibliojwt.restcontroller;

import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.model.dto.ApiResponseDTO;
import org.lessons.java.spec.bibliojwt.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminRestController {

    private final UserService userService;

    public AdminRestController(UserService userService) { this.userService = userService; }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponseDTO> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(new ApiResponseDTO(true, "Lista utenti recuperata", users));
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponseDTO> adminTest() {
        return ResponseEntity.ok(new ApiResponseDTO(true, "Accesso admin confermato", null));
    }
}
