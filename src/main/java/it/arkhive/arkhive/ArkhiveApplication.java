package it.arkhive.arkhive;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class ArkhiveApplication {

    public static void main(String[] args) {
        System.out.println("VARIABLE TEST: " + System.getenv("POSTGRES_HOST"));
        SpringApplication.run(ArkhiveApplication.class, args);
    }

}
