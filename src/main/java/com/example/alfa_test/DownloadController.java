package com.example.alfa_test;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

@RestController
@RequestMapping("/api")
public class DownloadController {

    private final RestClient restClient = RestClient.create();

    @GetMapping("/download")
    public String download(@RequestParam String url) {

        try {
            java.net.URI uri = new java.net.URI(url);
            
            if (!url.startsWith("https://")) {
                return "Error: https only";
            }

            return restClient.get().uri(url).retrieve().body(String.class);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

