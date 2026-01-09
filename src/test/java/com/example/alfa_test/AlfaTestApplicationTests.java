package com.example.alfa_test;

import tools.jackson.databind.ObjectMapper; 
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;


@SpringBootTest(properties = {
    "app.ks.alias=babaika",
    "app.ks.pswd=babaika",
    "app.ks.path=src/test/resources/testKeystore.p12", 
    "app.download.path=target/downloads",
    "app.download.host=raw.githubusercontent.com",
    "app.download.ext=.png"
})

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
        
        MvcResult result = mockMvc.perform(post("/api/hash")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        HashResponse res = objectMapper.readValue(result.getResponse().getContentAsString(), HashResponse.class);
        assertNotNull(res.getHash());
        assertEquals(64, res.getHash().length()); 
    }

    @Test
    @DisplayName("test attached sign")
    void testAttSign() throws Exception {
        String data = "babaika";

        SignRequest signReq = new SignRequest(data, false, ".txt");

        MvcResult signRes = mockMvc.perform(post("/api/sign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signReq)))
                .andExpect(status().isOk())
                .andReturn();

        String signatureBase64 = objectMapper.readTree(signRes.getResponse().getContentAsString())
                .get("signature").asText();

        VerifyRequest verifyReq = new VerifyRequest(signatureBase64, null);
        
        MvcResult verifyRes = mockMvc.perform(post("/api/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(verifyReq)))
                .andExpect(status().isOk())
                .andReturn();

        VerifyResponse response = objectMapper.readValue(verifyRes.getResponse().getContentAsString(), VerifyResponse.class);
        
        assertTrue(response.isValid(), "invalid sign");
        String restored = new String(Base64.getDecoder().decode(response.getOrigData()));
        assertEquals(data, restored);
        assertEquals(".txt", response.getExtension());
    }

    @Test
    @DisplayName("test detached sign")
    void testDetSign() throws Exception {
        String origData = "babaika detached";

        SignRequest signReq = new SignRequest(origData, true, ".doc");
        MvcResult signRes = mockMvc.perform(post("/api/sign")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signReq)))
                .andExpect(status().isOk())
                .andReturn();

        String signatureBase64 = objectMapper.readTree(signRes.getResponse().getContentAsString())
                .get("signature").asText();

        VerifyRequest verifyReq = new VerifyRequest(signatureBase64, origData);
        MvcResult verifyRes = mockMvc.perform(post("/api/verify")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(verifyReq)))
                .andExpect(status().isOk())
                .andReturn();

        VerifyResponse response = objectMapper.readValue(verifyRes.getResponse().getContentAsString(), VerifyResponse.class);
        
        assertTrue(response.isValid(), "invalid sign");
        assertEquals(".doc", response.getExtension());
    }

    @Test
    @DisplayName("test enc and dec")
    void testEnc() throws Exception {
        String secret = "babaika";

        EncRequest encReq = new EncRequest(secret);
        MvcResult encResult = mockMvc.perform(post("/api/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(encReq)))
                .andExpect(status().isOk())
                .andReturn();

        EncResponse encResp = objectMapper.readValue(encResult.getResponse().getContentAsString(), EncResponse.class);
        assertNotNull(encResp.getData());
        assertNotNull(encResp.getKey());
        assertNotNull(encResp.getIv());

        MvcResult decResult = mockMvc.perform(post("/api/decrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(encResp)))
                .andExpect(status().isOk())
                .andReturn();

        String decryptedText = decResult.getResponse().getContentAsString();
        assertEquals(secret, decryptedText, "invalid pt");
    }

    @Test
    @DisplayName("test down")
    void testDownload() throws Exception {
        String targetUrl = "https://raw.githubusercontent.com/cR4-sh/winter-ad-training25/refs/heads/main/services/pickme-house/web/static/hellososity.png";

        MvcResult result = mockMvc.perform(get("/api/download")
                .param("url", targetUrl))
                .andExpect(status().isOk()) 
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, org.hamcrest.Matchers.containsString("hellososity.png")))
                .andReturn();

        assertEquals(MediaType.APPLICATION_OCTET_STREAM_VALUE, result.getResponse().getContentType());
        
        byte[] downloadedFile = result.getResponse().getContentAsByteArray();
        assertNotNull(downloadedFile);
        assertTrue(downloadedFile.length > 0, "Downloaded file is empty");
        
        assertEquals((byte) 0x89, downloadedFile[0]);
        assertEquals((byte) 0x50, downloadedFile[1]);
    }
}