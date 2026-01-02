package com.example.alfa_test;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class SignController {

    private final Manager Manager;

    public SignController(Manager Manager) {
        this.Manager = Manager;
    }

    @PostMapping("/sign")
    public SignResponse sign(@RequestBody SignRequest request) {
        try {
            String signature = Manager.signData(request.getData());
            return new SignResponse(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return new SignResponse("Error: " + e.getMessage());
        }
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@RequestBody VerifyRequest request) {
        try {
            return Manager.verifyData(request.getSignature());
        } catch (Exception e) {
            e.printStackTrace();
            return new VerifyResponse(false, "Error: " + e.getMessage(), "Unknown");
        }
    }
}