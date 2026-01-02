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
    public EncResponse encrypt(@RequestBody EncRequest request) {
        try {
            return Manager.encryptData(request.getData());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody EncResponse request) {
        try {
            return Manager.decryptData(
                request.getData(), 
                request.getKey(), 
                request.getIv()
            );
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}