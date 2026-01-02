package com.example.alfa_test;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorBody> handleAllExceptions(Exception e) {
        return new ResponseEntity<>(
            new ErrorBody("Security Error", e.getMessage()), 
            HttpStatus.INTERNAL_SERVER_ERROR
        );
    }

    @Data
    @AllArgsConstructor
    static class ErrorBody {
        private String type;
        private String message;
    }
}