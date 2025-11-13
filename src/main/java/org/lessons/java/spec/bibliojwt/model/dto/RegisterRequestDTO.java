package org.lessons.java.spec.bibliojwt.model.dto;

import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisterRequestDTO {

    @NotBlank(message = "Email è obbligatoria")
    @Email(message = "Email non valida")
    private String email;

    @NotBlank(message = "Password è obbligatoria")
    @Size(min = 6, max = 100, message = "Password deve essere tra 6 e 100 caratteri")
    private String password;

    @NotBlank(message = "Nome è obbligatorio")
    private String firstName;

    @NotBlank(message = "Cognome è obbligatorio")
    private String lastName;

    @Column(nullable = false)
    private String role; 

    public RegisterRequestDTO() {}
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}
