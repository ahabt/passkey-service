package com.example.passkey.controller;

import ch.qos.logback.core.testUtil.RandomUtil;
import java.util.Map;
import java.util.Map.Entry;
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
@RequestMapping("/api")
public class BridgeController {

  private static final Logger logger = LoggerFactory.getLogger(BridgeController.class);

  // Simple in-memory store for PoC (Use Redis for Production)
  private final Map<String, String> signatureStore = new ConcurrentHashMap<>();
  private final Map<String, Map<String, String>> publicKeyStore = new ConcurrentHashMap<>();
  private final Map<String, String> challengeStore = new ConcurrentHashMap<>();

  // 1. App calls this after scanning QR and signing
  @PostMapping("/register-device")
  public ResponseEntity<Map<String, Object>> registerDevice(@RequestBody Map<String, String> payload) {
    String sessionId = payload.getOrDefault("sessionID", "unknown-session");

    publicKeyStore.put(sessionId, payload);
    return ResponseEntity.ok(Map.of("status", "registered", "sessionID", sessionId));
  }

  // 2. Desktop Browser calls this every 2 seconds
  @PostMapping("/authenticate")
  public ResponseEntity<Map<String, Object>> authenticate(@RequestBody Map<String, String> payload)
      throws Exception {

    boolean isValid;
    for (Entry<String, Map<String, String>> entry : publicKeyStore.entrySet()) {
      logger.info("Veriyfying signature with Public Key Store Entry: {} ", entry.getKey());
      String signature = payload.get("signature");
      String originalChallenge = entry.getValue().get("challenge");
      String userPublicKey = entry.getValue().get("publicKey");
      // Perform the ECDSA Verification logic here (from previous step)
      isValid = FidoVerifier.verify(userPublicKey, originalChallenge, signature);
      if (isValid) {
        logger.info("Signature verified: true");
        return ResponseEntity.ok(Map.of("status", "authenticated", "valid", "true"));
      }
    }

    logger.info("Signature verified: false");
    return ResponseEntity.ok(Map.of("status", "authenticated", "valid", "false"));
  }
}