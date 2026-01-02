package com.example.alfa_test;

import org.springframework.web.bind.annotation.*;
import java.security.MessageDigest;
import java.util.HexFormat;

@RestController
@RequestMapping("/api") 

public class HashController {

    @PostMapping("/hash")
    public HashResponse calculateHash(@RequestBody HashRequest request) {
        try {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(request.getData().getBytes());            
            String res = HexFormat.of().formatHex(hashBytes);
            return new HashResponse(res);
            
        } catch (Exception e) {
            return new HashResponse("Error: " + e.getMessage());
        }
    }
}