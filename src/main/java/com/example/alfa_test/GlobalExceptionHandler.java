package com.example.alfa_test;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler({
        IllegalArgumentException.class, 
        org.bouncycastle.cms.CMSException.class,
        NullPointerException.class 
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception e) {
        log.warn("Client Error: {}", e.getMessage());
        return buildResponse("Bad Request: check input data", HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAllExceptions(Exception e) {
        log.error("Server Error: ", e);
        return buildResponse("Internal Server Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private ResponseEntity<ErrorResponse> buildResponse(String message, HttpStatus status) {
        ErrorResponse error = new ErrorResponse();
        error.setType("Security Error");
        error.setMessage(message);
        error.setStatus(status.value());
        error.setTimestamp(LocalDateTime.now().toString());
        return new ResponseEntity<>(error, status);
    }

    @Data
    public static class ErrorResponse {
        private String type;
        private String message;
        private int status;
        private String timestamp;
    }
}