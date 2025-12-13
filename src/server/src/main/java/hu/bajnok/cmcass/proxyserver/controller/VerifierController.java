package hu.bajnok.cmcass.proxyserver.controller;

import hu.bajnok.cmcass.proxyserver.service.DataBaseService;
import hu.bajnok.cmcass.proxyserver.service.EnclaveService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@RestController
@RequestMapping("/verifier")
public class VerifierController {

    private final EnclaveService enclaveService;
    private final DataBaseService userDetailsService;
    private static final Logger logger = LoggerFactory.getLogger(VerifierController.class);

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

        logger.info("User [{}] is initiating a verifier enclave.", username);
        String enclavePublicKey_b64 = enclaveService.launchEnclave(username);

        return ResponseEntity.ok(enclavePublicKey_b64);
    }

    @PostMapping(value = "/agree", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> agreeWithEnclave(@AuthenticationPrincipal UserDetails user,
                                                   @RequestParam("clientData") String clientDataB64,
                                                   @RequestParam("publicKey") String processKey) {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated");
        }

        logger.info("User [{}] isshaking hands with the enclave.", username);
        enclaveService.shakeHands(username, clientDataB64, processKey);

        return ResponseEntity.ok("Successfully agreed on the shared encryption key.");
    }

    @GetMapping("/quote")
    public ResponseEntity<String> getEnclaveQuote(@AuthenticationPrincipal UserDetails user,
                                                  @RequestParam("publicKey") String processKey,
                                                  @RequestParam("encryptedNonce") String encryptedNonceB64) {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated");
        }

        logger.info("User [{}] is requesting the enclave quote.", username);
        String quoteB64 = enclaveService.getEnclaveQuote(username, processKey, encryptedNonceB64);

        return ResponseEntity.ok(quoteB64);
    }

    /**
     * Process uploaded file
     * @param file MultipartFile object
     * @param processKey Public key of the enclave process
     * @param user Authenticated user details
     * @return Encrypted output file
     */
    @PostMapping(value = "/process", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> processEncryptedFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("processKey") String processKey,
            @AuthenticationPrincipal UserDetails user) {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated");
        }

        logger.info("User [{}] is initiating a verification process.", username);

        try {
            Path tempFilePath = Files.createTempFile("upload_", ".zip");
            file.transferTo(tempFilePath);

            enclaveService.createVerificationJob(username, tempFilePath, processKey);

            return ResponseEntity.ok("Verification in progress.");
        }
        catch (Exception e) {
            return ResponseEntity.badRequest().body("Error during verification: " + e.getMessage());
        }

    }

    @GetMapping(value = "/process", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> getEncryptedResults(
            @RequestParam("publicKey") String processKey,
            @AuthenticationPrincipal UserDetails user) {
        String username = (user != null) ? user.getUsername() : null;
        if (username == null) {
            return ResponseEntity.badRequest().body("No user authenticated".getBytes());
        }

        logger.info("User [{}] is requesting the encrypted results for enclave with public key {}.", username, processKey);

        try {
            byte[] encryptedOutputFile = enclaveService.getEncryptedResults(username, processKey);

            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(encryptedOutputFile);
        }
        catch (Exception e) {
            return ResponseEntity.badRequest().body(("Error retrieving the results: " + e.getMessage()).getBytes());
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

        logger.info("User [{}] is stopping a verifier process.", username);

        enclaveService.stop_enclave(username, processKey);

        return ResponseEntity.ok("Verification stopped successfully");
    }

    /**
     * Register a new user
     * @param payload Request body containing username and password
     * @return Response message
     */
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Map<String, String> payload) {
        String username = payload.get("username");
        String password = payload.get("password");
        try {
            userDetailsService.registerUser(username, password);
            return ResponseEntity.ok("User registered successfully");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());

        }
    }
}