package com.example.alfa_test;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.beans.factory.annotation.Value;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;


@RestController
@RequestMapping("/api")
public class DownloadController {

    @Value("${app.download.path}")
    private String downPath;

    @Value("${app.download.ext}")
    private String downExt;

    @Value("${app.download.host}")
    private String downHost;

    private final RestClient restClient = RestClient.create();

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam String url) {
        try {

            if (!url.startsWith("https://")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            List<String> trustedHosts = Arrays.asList(downHost.split(","));
            boolean isTrusted = trustedHosts.stream().anyMatch(url::startsWith);
            if (!isTrusted) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            if (url.contains("github.com") && url.contains("/blob/")) {
                url = url.replace("github.com", "raw.githubusercontent.com")
                    .replace("/blob/", "/");
            }

            String fileName = url.substring(url.lastIndexOf('/') + 1);
            if (fileName.contains("?")) fileName = fileName.substring(0, fileName.indexOf('?'));
            
            String ext = fileName.contains(".") ? fileName.substring(fileName.lastIndexOf('.')) : "";
            List<String> yesExts = Arrays.asList(downExt.split(","));
            
            if (!yesExts.contains(ext.toLowerCase())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            byte[] fileData = restClient.get().uri(url).retrieve().body(byte[].class);
            if (fileData == null) return ResponseEntity.notFound().build();

            Path path = Paths.get(downPath).resolve(fileName).normalize();

            if (!path.startsWith(Paths.get(downPath))) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            Files.write(path, fileData);

            Resource resource = new FileSystemResource(path);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                    .body(resource);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}