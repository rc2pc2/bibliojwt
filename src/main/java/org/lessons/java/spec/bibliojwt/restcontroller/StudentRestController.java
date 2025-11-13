package org.lessons.java.spec.bibliojwt.restcontroller;

import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.model.dto.ApiResponseDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/student")
public class StudentRestController {

    @GetMapping("/profile")
    public ResponseEntity<ApiResponseDTO> getProfile(@AuthenticationPrincipal User user) {
        Map<String, Object> profileData = new HashMap<>();
        profileData.put("email", user.getEmail());
        profileData.put("fullName", user.getFirstName() + " " + user.getLastName());
        profileData.put("role", user.getRole());
        ApiResponseDTO resp = new ApiResponseDTO(true, "Profilo recuperato con successo", profileData);
        return ResponseEntity.ok(resp);
    }

    @GetMapping("/courses")
    public ResponseEntity<ApiResponseDTO> getMyCourses(@AuthenticationPrincipal User user) {
        ApiResponseDTO resp = new ApiResponseDTO(true, "Lista corsi per: " + user.getEmail(), null);
        return ResponseEntity.ok(resp);
    }
}
