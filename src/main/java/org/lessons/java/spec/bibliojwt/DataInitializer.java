package org.lessons.java.spec.bibliojwt;

import org.lessons.java.spec.bibliojwt.model.Role;
import org.lessons.java.spec.bibliojwt.model.User;
import org.lessons.java.spec.bibliojwt.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() > 0) return;

        // Password per tutti gli utenti: 123456
        String commonPassword = "123456";

        User admin = new User();
        admin.setEmail("admin@univ.it");
        admin.setPassword(passwordEncoder.encode(commonPassword));
        admin.setFirstName("Mario");
        admin.setLastName("Rossi");
        admin.setRole(Role.ROLE_ADMIN);
        admin.setEnabled(true);
        userRepository.save(admin);
        System.out.println("✅ Admin creato: admin@univ.it / 123456");

        User mod = new User();
        mod.setEmail("mod@univ.it");
        mod.setPassword(passwordEncoder.encode(commonPassword));
        mod.setFirstName("Laura");
        mod.setLastName("Bianchi");
        mod.setRole(Role.ROLE_MODERATOR);
        mod.setEnabled(true);
        userRepository.save(mod);
        System.out.println("✅ Moderator creato: mod@univ.it / 123456");

        User user = new User();
        user.setEmail("user@univ.it");
        user.setPassword(passwordEncoder.encode(commonPassword));
        user.setFirstName("Giovanni");
        user.setLastName("Verdi");
        user.setRole(Role.ROLE_USER);
        user.setEnabled(true);
        userRepository.save(user);
        System.out.println("✅ User creato: user@univ.it / 123456");
    }
}
