package com.example.alfa_test;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@RestController
@RequestMapping("/api")
public class SignController {

    private final Manager Manager;

    public SignController(Manager Manager) {
        this.Manager = Manager;
    }

    @PostMapping("/sign")
    public SignResponse sign(@RequestBody SignRequest request) throws Exception {
        String sig = Manager.signData(request.getOrigData(), request.isDetached(), request.getExtension());
        return new SignResponse(sig);
    }

    @PostMapping("/verify")
    public VerifyResponse verify(@RequestBody VerifyRequest request) throws Exception {
        return Manager.verifyData(request.getSignature(), request.getOrigData());
    }
}