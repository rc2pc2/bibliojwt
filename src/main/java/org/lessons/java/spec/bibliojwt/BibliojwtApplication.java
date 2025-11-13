package org.lessons.java.spec.bibliojwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling  // Abilita job schedulati (es. pulizia refresh token)
public class BibliojwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(BibliojwtApplication.class, args);
	}

}
