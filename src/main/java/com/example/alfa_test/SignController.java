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
    public SignResponse sign(@RequestBody SignRequest request) throws Exception {
        String signature = Manager.signData(request.getData(), request.isDetached());
        return new SignResponse(signature);
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@RequestBody VerifyRequest request) throws Exception {
        return Manager.verifyData(request.getSignature(), request.getData());
    }
}