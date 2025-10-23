package hu.bajnok.cmcass.proxyserver.service;

import hu.bajnok.cmcass.proxyserver.model.Process;
import hu.bajnok.cmcass.proxyserver.model.User;
import hu.bajnok.cmcass.proxyserver.repository.ProcessRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import hu.bajnok.cmcass.proxyserver.repository.UserRepository;

@Service
public class DataBaseService {

    private final UserRepository userRepository;
    private final ProcessRepository processRepository;
    private final PasswordEncoder passwordEncoder;
    private static final Logger logger = LoggerFactory.getLogger(DataBaseService.class);

    public DataBaseService(UserRepository userRepository, ProcessRepository processRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.processRepository = processRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void addProcess(String username, int port, String processKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        Process process = new Process();
        process.setPort(port);
        process.setKey(processKey);
        user.addProcess(process);
        processRepository.save(process);
    }

    public int getProcessPort(String username, String processKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Process process = processRepository.findByKeyAndUser_Id(processKey, user.getId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid process key"));

        return process.getPort();
    }

    @Transactional
    public void stopProcess(String username, String processKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        processRepository.deleteByKeyAndUser_Id(processKey, user.getId());
        userRepository.save(user);
    }

    public int getNewProcessPort() {
        return processRepository.findAllProcessPorts().stream()
                .max(Integer::compareTo)
                .orElse(0) + 1;
    }

    @Transactional
    public void registerUser(String username, String password) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("USER");
        userRepository.save(user);
    }
}
