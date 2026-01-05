package com.example.alfa_test;

import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api")
public class HashController {

    private final Manager Manager; 

    public HashController(Manager Manager) {
        this.Manager = Manager;
    }

    @PostMapping("/hash")
    public HashResponse hashData(@RequestBody HashRequest request) throws Exception {
        String res = Manager.hashData(request.getData());
        return new HashResponse(res);
    }
}