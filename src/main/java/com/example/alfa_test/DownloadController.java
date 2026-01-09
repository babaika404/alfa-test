package com.example.alfa_test;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@Slf4j
@RestController
@RequestMapping("/api")
public class DownloadController {

    @Value("${app.download.path}")
    private String downPath;

    @Value("${app.download.ext}")
    private String downExt;

    @Value("${app.download.host}")
    private String downHost;

    private List<String> downHosts;
    private List<String> downExts;
    private Path rootPath;

    private final RestClient restClient = RestClient.create();

    @PostConstruct
    public void init() {
        this.downHosts = Stream.of(downHost.split(","))
                .map(String::trim)
                .collect(Collectors.toList());

        this.downExts = Stream.of(downExt.split(","))
                .map(String::trim)
                .map(String::toLowerCase)
                .collect(Collectors.toList());

        this.rootPath = Paths.get(downPath).toAbsolutePath().normalize();
        
        try {
            Files.createDirectories(rootPath);
        } catch (Exception e) {
            log.info("Could not create download directory: {}", e);
        }
    }

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam String url) {
        try {

            if (!url.startsWith("https://")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            URI uri = new URI(url);
            String currentHost = uri.getHost();

            if (currentHost == null || !downHosts.contains(currentHost)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }

            String pathStr = uri.getPath();
            String fileName = pathStr.substring(pathStr.lastIndexOf('/') + 1);
            
            if (fileName.isEmpty()) return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();

            String ext = fileName.contains(".") ? fileName.substring(fileName.lastIndexOf('.')).toLowerCase() : "";
            
            if (!downExts.contains(ext)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            byte[] fileData = restClient.get().uri(url).retrieve().body(byte[].class);
            if (fileData == null) return ResponseEntity.notFound().build();

            Path targetPath = rootPath.resolve(fileName).normalize();

            if (!targetPath.startsWith(rootPath)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            Files.write(targetPath, fileData);

            Resource resource = new FileSystemResource(targetPath);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                    .body(resource);

        } catch (Exception e) {
            log.error("Download failed for url={}", url, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}