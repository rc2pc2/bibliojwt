package org.lessons.java.spec.bibliojwt.exception;

import org.lessons.java.spec.bibliojwt.model.dto.ApiResponseDTO;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponseDTO> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, ex.getMessage(), null);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiResponseDTO> handleUsernameNotFound(UsernameNotFoundException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, "Utente non trovato", null);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponseDTO> handleBadCredentials(BadCredentialsException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, "Email o password non corretti", null);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiResponseDTO> handleExpiredJwt(ExpiredJwtException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, "Token scaduto, effettua nuovamente il login", null);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<ApiResponseDTO> handleMalformedJwt(MalformedJwtException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, "Token non valido", null);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiResponseDTO> handleInvalidToken(InvalidTokenException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, ex.getMessage(), null);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponseDTO> handleResourceNotFound(ResourceNotFoundException ex) {
        ApiResponseDTO response = new ApiResponseDTO(false, ex.getMessage(), null);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDTO> handleGenericException(Exception ex) {
        ex.printStackTrace();
        ApiResponseDTO response = new ApiResponseDTO(false, "Si è verificato un errore interno", null);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
