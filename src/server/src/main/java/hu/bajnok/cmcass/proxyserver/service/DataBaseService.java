package hu.bajnok.cmcass.proxyserver.service;

import hu.bajnok.cmcass.proxyserver.model.Process;
import hu.bajnok.cmcass.proxyserver.model.User;
import hu.bajnok.cmcass.proxyserver.repository.ProcessRepository;
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

    public void addProcess(String username, int processId, String processKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        Process process = new Process();
        process.setId(processId);
        process.setKey(processKey);
        process.setUser(user);
        processRepository.save(process);
        userRepository.save(user);
    }

    public int getProcessId(String username, String processKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return processRepository.findByKeyAndUserId(processKey, user.getId())
                .orElseThrow(() -> new IllegalArgumentException("Invalid process key"))
                .getId();
    }

    public void stopProcess(String username, String processKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        processRepository.deleteByKeyAndUser_Id(processKey, user.getId());
        userRepository.save(user);
    }

    public int getNewProcessId() {
        return processRepository.findAllProcessIds().stream()
                .max(Integer::compareTo)
                .orElse(0) + 1;
    }

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
