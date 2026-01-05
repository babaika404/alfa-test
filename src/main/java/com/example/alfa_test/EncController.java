package com.example.alfa_test;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class EncController {

    private final Manager Manager;

    public EncController(Manager Manager) {
        this.Manager = Manager;
    }

    @PostMapping("/encrypt")
    public EncResponse encrypt(@RequestBody EncRequest request) throws Exception {
        return Manager.encryptData(request.getData());
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody EncResponse request) throws Exception {
        return Manager.decryptData(request.getData(), request.getKey(), request.getIv());
    }
}

