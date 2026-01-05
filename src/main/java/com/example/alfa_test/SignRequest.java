package com.example.alfa_test;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignRequest {
    private String origData;
    private boolean detached;
    private String extension; 
}