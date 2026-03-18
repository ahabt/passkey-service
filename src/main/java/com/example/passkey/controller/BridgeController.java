package com.example.passkey.controller;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/bridge")
public class BridgeController {

  private static final Logger logger = LoggerFactory.getLogger(BridgeController.class);

  // Simple in-memory store for PoC (Use Redis for Production)
  private final Map<String, String> signatureStore = new ConcurrentHashMap<>();
  private final Map<String, String> publicKeyStore = new ConcurrentHashMap<>();
  private final Map<String, String> challengeStore = new ConcurrentHashMap<>();

  // 1. App calls this after scanning QR and signing
  @PostMapping("/submit")
  public ResponseEntity<String> submitSignature(@RequestBody Map<String, String> payload) {
    logger.info("Received signature submission: {}", payload);
    String sessionId = payload.get("sessionID");
    String signature = payload.get("signature");
    String publicKey = payload.get("publicKey");
    String challenge = payload.get("challenge");

    signatureStore.put(sessionId, signature);
    publicKeyStore.put(sessionId, publicKey);
    challengeStore.put(sessionId, challenge);
    return ResponseEntity.ok("Signature Received");
  }

  // 2. Desktop Browser calls this every 2 seconds
  @GetMapping("/poll/{sessionId}")
  public ResponseEntity<Map<String, Object>> pollSignature(@PathVariable String sessionId)
      throws Exception {
    logger.info("Received signature poll: {}", sessionId);
    if (signatureStore.containsKey(sessionId)) {
      String signature = signatureStore.remove(sessionId);
      String userPublicKey = publicKeyStore.remove(sessionId);
      String originalChallenge = challengeStore.remove(sessionId);

      // Perform the ECDSA Verification logic here (from previous step)
      boolean isValid = FidoVerifier.verify(userPublicKey, originalChallenge, signature);

      logger.info("Signature verified: {}", isValid);
      return ResponseEntity.ok(Map.of("status", "authenticated", "valid", isValid));
    }
    logger.warn("Signature not found: {}", sessionId);
    return ResponseEntity.ok(Map.of("status", "pending"));
  }
}