package hu.bajnok.cmcass.proxyserver;

import hu.bajnok.cmcass.proxyserver.model.User;
import hu.bajnok.cmcass.proxyserver.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class UserInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if(userRepository.findByUsername("client1").isEmpty()) {
            User user = new User();
            user.setUsername("client1");
            user.setPassword(passwordEncoder.encode("secret123"));
            user.setRole("USER");
            userRepository.save(user);
        }
    }
}
