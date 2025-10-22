package hu.bajnok.controller;

import hu.bajnok.service.DataBaseService;
import hu.bajnok.service.EnclaveService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;

@RestController
@RequestMapping("/verifier")
public class VerifierController {

    private final EnclaveService enclaveService;
    private final DataBaseService userDetailsService;

    public VerifierController(EnclaveService enclaveService, DataBaseService userDetailsService) {
        this.enclaveService = enclaveService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Initiate enclave process
     * This request starts an enclave process attached to the authenticated user's ID
     * @param user Authenticated user details
     * @return Base64 encoded public key
     * @throws Exception if the enclave is not running
     */
    @GetMapping("/init")
    public ResponseEntity<String> initEnclave(@AuthenticationPrincipal UserDetails user) throws Exception {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated");
        }

        System.out.println("User [" + username + "] is initiating a verifier enclave.");
        String enclavePublicKey_b64 = enclaveService.launch_enclave(user.getUsername());

        return ResponseEntity.ok(enclavePublicKey_b64);
    }

    /**
     * Process uploaded file
     * @param file MultipartFile object
     * @param clientDataB64 Base64 encoded clientData
     * @param processKey Public key of the enclave process
     * @param user Authenticated user details
     * @return Encrypted output file
     */
    @PostMapping(value = "/process", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> processEncryptedFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("clientData") String clientDataB64,
            @RequestParam("publicKey") String processKey,
            @AuthenticationPrincipal UserDetails user) {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated".getBytes());
        }

        System.out.println("User [" + username + "] is initiating a verification process.");

        try {
            Path encryptedOutputFilePath = enclaveService.process_task(username, file, clientDataB64, processKey);

            byte[] encryptedFile = Files.readAllBytes(encryptedOutputFilePath);
            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\""
                            + encryptedOutputFilePath.getFileName() + "\"")
                    .body(encryptedFile);
        }
        catch (Exception e) {
            return ResponseEntity.status(500).body(("Error processing file: " + e.getMessage()).getBytes());
        }

    }

    /**
     * Stop enclave process
     * @param processKey Public key of the enclave process
     * @param user Authenticated user details
     * @return Response message
     */
    @PostMapping("/kill")
    public ResponseEntity<String> killProcess(@RequestParam("publicKey") String processKey, @AuthenticationPrincipal UserDetails user) {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated");
        }

        System.out.println("User [" + username + "] is stopping a verifier process.");

        enclaveService.stop_enclave(username, processKey);

        return ResponseEntity.ok("Verification stopped successfully");
    }

    /**
     * Register a new user
     * @param username username
     * @param password password
     * @return Response message
     */
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestParam("username") String username, @RequestParam("password") String password) {
        try {
            userDetailsService.registerUser(username, password);
            return ResponseEntity.ok("User registered successfully");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());

        }
    }
}