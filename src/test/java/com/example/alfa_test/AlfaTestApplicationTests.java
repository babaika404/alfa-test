package com.example.alfa_test;

import tools.jackson.databind.ObjectMapper; 

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc 
class AlfaTestApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper; 

    @Test
    @DisplayName("test hash")
    void testHash() throws Exception {
        HashRequest request = new HashRequest("babaika");
        
        mockMvc.perform(post("/api/hash")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("test attached sign")
    void testAttachedSign() throws Exception {
        String data = "babaika";

        SignRequest signReq = new SignRequest(data, false);

		MvcResult signResult = mockMvc.perform(post("/api/sign")
				.contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(signReq)))
				.andExpect(status().isOk()) 
				.andReturn();

        String signatureBase64 = objectMapper.readTree(signResult.getResponse().getContentAsString())
                .get("signature").asText();

        VerifyRequest verifyReq = new VerifyRequest(signatureBase64, null);
        MvcResult verifyResult = mockMvc.perform(post("/api/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(verifyReq)))
                .andReturn();

        VerifyResponse response = objectMapper.readValue(verifyResult.getResponse().getContentAsString(), VerifyResponse.class);
        
        assertTrue(response.isValid(), "invalid sign");
        assertEquals(data, response.getData());
    }

    @Test
    @DisplayName("test detached sign")
    void testDetachedSign() throws Exception {
        String originalData = "babaika";

        SignRequest signReq = new SignRequest(originalData, true);
        MvcResult signResult = mockMvc.perform(post("/api/sign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signReq)))
                .andReturn();

        String signatureBase64 = objectMapper.readTree(signResult.getResponse().getContentAsString())
                .get("signature").asText();

        VerifyRequest verifyReq = new VerifyRequest(signatureBase64, originalData);
        MvcResult verifyResult = mockMvc.perform(post("/api/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(verifyReq)))
                .andReturn();

        VerifyResponse response = objectMapper.readValue(verifyResult.getResponse().getContentAsString(), VerifyResponse.class);
        
        assertTrue(response.isValid(), "invalid sign");
    }

    @Test
    @DisplayName("test enc and dec")
    void testEncryptionCycle() throws Exception {
        String secret = "babaika";

        EncRequest encReq = new EncRequest(secret);
        MvcResult encResult = mockMvc.perform(post("/api/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(encReq)))
                .andReturn();

        EncResponse encResp = objectMapper.readValue(encResult.getResponse().getContentAsString(), EncResponse.class);

        MvcResult decResult = mockMvc.perform(post("/api/decrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(encResp)))
                .andReturn();

        String decryptedText = decResult.getResponse().getContentAsString();
        assertEquals(secret, decryptedText, "invalid pt");
    }


    @Test
    @DisplayName("test GEH")
    void testErrorHandler() throws Exception {
        mockMvc.perform(post("/api/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
                .andExpect(status().isBadRequest()); 
    }
}