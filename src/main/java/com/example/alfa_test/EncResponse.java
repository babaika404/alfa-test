package com.example.alfa_test;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncResponse {
    private String data; 
    private String key; 
    private String iv;
}