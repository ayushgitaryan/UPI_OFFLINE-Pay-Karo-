package com.demo.upimesh.controller;

import com.demo.upimesh.crypto.ServerKeyHolder;
import com.demo.upimesh.model.*;
import com.demo.upimesh.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.*;

/**
 * Public REST surface.
 *
 * The endpoints split into three groups:
 *   /api/server-key      → so simulated senders can fetch the server's public key
 *   /api/mesh/*          → simulator endpoints (inject, gossip, flush)
 *   /api/bridge/ingest   → THE real production endpoint a real bridge node would hit
 *   /api/accounts, /api/transactions → for the dashboard
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired private ServerKeyHolder serverKey;
    @Autowired private DemoService demo;
    @Autowired private MeshSimulatorService mesh;
    @Autowired private BridgeIngestionService bridge;
    @Autowired private AccountRepository accountRepo;
    @Autowired private TransactionRepository txRepo;
    @Autowired private IdempotencyService idempotency;

    // ------------------------------------------------------------------ key

    @GetMapping("/server-key")
    public Map<String, String> getServerPublicKey() {
        return Map.of(
                "publicKey", serverKey.getPublicKeyBase64(),
                "algorithm", "RSA-2048 / OAEP-SHA256",
                "hybridScheme", "RSA-OAEP encrypts an AES-256-GCM session key"
        );
    }

    // ---------------------------------------------------------------- demo

    /**
     * Demo helper: build a packet on the server (simulating a sender phone)
     * and inject it into the mesh at the given device.
     */
    @PostMapping("/demo/send")
    public ResponseEntity<?> demoSend(@RequestBody DemoSendRequest req) throws Exception {
        MeshPacket packet = demo.createPacket(
                req.senderVpa, req.receiverVpa, req.amount, req.pin,
                req.ttl == null ? 5 : req.ttl);

        String startDevice = req.startDevice == null ? "phone-alice" : req.startDevice;
        mesh.inject(startDevice, packet);

        return ResponseEntity.ok(Map.of(
                "packetId", packet.getPacketId(),
                "ciphertextPreview", packet.getCiphertext().substring(0, 64) + "...",
                "ttl", packet.getTtl(),
                "injectedAt", startDevice
        ));
    }

    public static class DemoSendRequest {
        public String senderVpa;
        public String receiverVpa;
        public BigDecimal amount;
        public String pin;
        public Integer ttl;
        public String startDevice;
    }

    // -------------------------------------------------------------- mesh sim

    @GetMapping("/mesh/state")
    public Map<String, Object> meshState() {
        List<Map<String, Object>> deviceData = new ArrayList<>();
        for (VirtualDevice d : mesh.getDevices()) {
            List<Map<String, Object>> packetList = new ArrayList<>();
            for (MeshPacket p : d.getHeldPackets()) {
                String ct = p.getCiphertext();
                packetList.add(Map.of(
                        "packetId", p.getPacketId(),
                        "shortId", p.getPacketId().length() > 8 ? p.getPacketId().substring(0, 8) : p.getPacketId(),
                        "ttl", p.getTtl(),
                        "createdAt", p.getCreatedAt(),
                        "ciphertextPreview", ct.length() > 36 ? ct.substring(0, 36) + "..." : ct,
                        "ciphertextLength", ct.length()
                ));
            }
            deviceData.add(Map.of(
                    "deviceId", d.getDeviceId(),
                    "hasInternet", d.hasInternet(),
                    "packetCount", d.packetCount(),
                    "packetIds", d.getHeldPackets().stream()
                            .map(p -> p.getPacketId().substring(0, 8))
                            .toList(),
                    "packets", packetList
            ));
        }
        return Map.of(
                "devices", deviceData,
                "idempotencyCacheSize", idempotency.size()
        );
    }

    @PostMapping("/mesh/device/toggle-internet")
    public Map<String, Object> toggleInternet(@RequestBody Map<String, String> body) {
        String deviceId = body.get("deviceId");
        boolean state = mesh.toggleInternet(deviceId);
        return Map.of("deviceId", deviceId, "hasInternet", state);
    }

    @PostMapping("/mesh/device/add")
    public Map<String, Object> addDevice(@RequestBody Map<String, Object> body) {
        String deviceId = (String) body.getOrDefault("deviceId", "phone-node-" + (System.currentTimeMillis() % 10000));
        boolean hasInternet = Boolean.TRUE.equals(body.get("hasInternet"));
        VirtualDevice d = mesh.addDevice(deviceId, hasInternet);
        return Map.of("deviceId", d.getDeviceId(), "hasInternet", d.hasInternet());
    }

    @PostMapping("/mesh/device/remove")
    public Map<String, Object> removeDevice(@RequestBody Map<String, String> body) {
        String deviceId = body.get("deviceId");
        boolean removed = mesh.removeDevice(deviceId);
        return Map.of("deviceId", deviceId, "removed", removed);
    }

    @PostMapping("/demo/tamper")
    public Map<String, Object> tamperPacket(@RequestBody Map<String, String> body) {
        String deviceId = body.getOrDefault("deviceId", "phone-stranger1");
        String packetId = body.get("packetId");
        boolean tampered = mesh.tamperPacket(deviceId, packetId);
        return Map.of("deviceId", deviceId, "tampered", tampered);
    }

    @PostMapping("/demo/replay")
    public ResponseEntity<?> replayAttack(@RequestBody Map<String, String> body) {
        String deviceId = body.getOrDefault("deviceId", "phone-bridge");
        VirtualDevice d = mesh.getDevice(deviceId);
        if (d != null && !d.getHeldPackets().isEmpty()) {
            MeshPacket packet = d.getHeldPackets().iterator().next();
            BridgeIngestionService.IngestResult r = bridge.ingest(packet, "mallory-rogue-bridge", 0);
            return ResponseEntity.ok(r);
        }
        return ResponseEntity.badRequest().body(Map.of("error", "No packet found on " + deviceId + " to replay"));
    }

    @PostMapping("/demo/reset-accounts")
    public Map<String, Object> resetAccounts() {
        accountRepo.deleteAll();
        demo.seedAccounts();
        return Map.of("status", "accounts reset");
    }

    @PostMapping("/mesh/gossip")
    public Map<String, Object> meshGossip() {
        MeshSimulatorService.GossipResult r = mesh.gossipOnce();
        return Map.of(
                "transfers", r.transfers(),
                "deviceCounts", r.deviceCounts()
        );
    }

    @PostMapping("/mesh/flush")
    public Map<String, Object> meshFlush() {
        List<MeshSimulatorService.BridgeUpload> uploads = mesh.collectBridgeUploads();

        List<Map<String, Object>> results = new ArrayList<>();
        uploads.parallelStream().forEach(up -> {
            BridgeIngestionService.IngestResult r =
                    bridge.ingest(up.packet(), up.bridgeNodeId(), 5 - up.packet().getTtl());
            synchronized (results) {
                results.add(Map.of(
                        "bridgeNode", up.bridgeNodeId(),
                        "packetId", up.packet().getPacketId().substring(0, 8),
                        "outcome", r.outcome(),
                        "reason", r.reason() == null ? "" : r.reason(),
                        "transactionId", r.transactionId() == null ? -1 : r.transactionId()
                ));
            }
        });

        return Map.of(
                "uploadsAttempted", uploads.size(),
                "results", results
        );
    }

    @PostMapping("/mesh/reset")
    public Map<String, Object> meshReset() {
        mesh.resetMesh();
        idempotency.clear();
        return Map.of("status", "mesh and idempotency cache cleared");
    }

    @PostMapping("/bridge/ingest")
    public ResponseEntity<?> ingest(
            @RequestBody MeshPacket packet,
            @RequestHeader(value = "X-Bridge-Node-Id", defaultValue = "unknown") String bridgeNodeId,
            @RequestHeader(value = "X-Hop-Count", defaultValue = "0") int hopCount) {

        BridgeIngestionService.IngestResult r = bridge.ingest(packet, bridgeNodeId, hopCount);
        return ResponseEntity.ok(r);
    }

    @GetMapping("/accounts")
    public List<Account> listAccounts() {
        return accountRepo.findAll();
    }

    @GetMapping("/transactions")
    public List<Transaction> listTransactions() {
        return txRepo.findTop20ByOrderByIdDesc();
    }
}
