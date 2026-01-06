package com.example.alfa_test;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;

@Slf4j
@Service
public class Manager {

    @Value("${app.ks.pswd}")
    private String kspass;

    @Value("${app.ks.alias}")    
    private String ksalias;

    @Value("${app.ks.path}")     
    private String kspath;

    private PrivateKey privkey;
    private PublicKey pubkey;
    private X509Certificate cert;

    @PostConstruct
    public void init() throws Exception {

        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        
        log.info("key init");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = java.nio.file.Files.newInputStream(java.nio.file.Paths.get(kspath))) {
            ks.load(is, kspass.toCharArray());
        }

        this.privkey = (PrivateKey) ks.getKey(ksalias, kspass.toCharArray());
        this.cert = (X509Certificate) ks.getCertificate(ksalias);
        this.pubkey = cert.getPublicKey();
    }

    private byte[] prepareData(String input) {
        if (input == null || input.trim().isEmpty()) return new byte[0];

        String clean = input.trim().replace("\"", "").replaceAll("\\s", "");

        boolean is64 = clean.matches("^[a-zA-Z0-9+/]*={0,2}$") && (clean.length() % 4 == 0);
        boolean isFile = clean.contains("=") || clean.length() > 64;

        if (is64 && isFile) {
            try {
                return Base64.getDecoder().decode(clean);
            } catch (Exception e) {
                log.info("Failed to decode as b64");
            }
        }

        return input.getBytes(StandardCharsets.UTF_8);
    }

    public String signData(String data, boolean detached, String extension) throws Exception {
        log.info("start sign detached: ", detached);

        byte[] signB = prepareData(data);
        
        org.bouncycastle.asn1.ASN1ObjectIdentifier extOID = new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.55");
        org.bouncycastle.asn1.cms.Attribute extAttr = new org.bouncycastle.asn1.cms.Attribute(
                extOID, 
                new org.bouncycastle.asn1.DERSet(new org.bouncycastle.asn1.DERPrintableString(extension))
        );
        
        java.util.Hashtable<org.bouncycastle.asn1.ASN1ObjectIdentifier, org.bouncycastle.asn1.cms.Attribute> attrs = new java.util.Hashtable<>();
        attrs.put(extOID, extAttr);
        org.bouncycastle.asn1.cms.AttributeTable myAttrTable = new org.bouncycastle.asn1.cms.AttributeTable(attrs);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(privkey);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(myAttrTable))
                .build(signer, cert));
        
        gen.addCertificates(new JcaCertStore(java.util.Collections.singletonList(cert)));

        CMSTypedData msg = new CMSProcessableByteArray(signB);
        CMSSignedData sigData = gen.generate(msg, !detached); 
        
        return Base64.getEncoder().encodeToString(sigData.getEncoded());
    }

    public VerifyResponse verifyData(String sign64, String origData) throws Exception {
        log.info("start verify");
        
        byte[] signB = Base64.getDecoder().decode(sign64.trim().replace("\"", "").replaceAll("\\s", ""));
        CMSSignedData sigData;

        if (origData != null && !origData.trim().isEmpty()) {
            log.info("detached");
            byte[] origB = prepareData(origData);
            sigData = new CMSSignedData(new CMSProcessableByteArray(origB), signB);
        } else {
            log.info("attached");
            sigData = new CMSSignedData(signB);
        }

        SignerInformation signer = sigData.getSignerInfos().getSigners().iterator().next();
        
        var certMatches = sigData.getCertificates().getMatches(signer.getSID());
        org.bouncycastle.cert.X509CertificateHolder certHolder = (org.bouncycastle.cert.X509CertificateHolder) certMatches.iterator().next();
        X509Certificate verCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        boolean isValid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(verCert));

        String detectedExt = ".bin";
        AttributeTable attrTable = signer.getSignedAttributes();
        if (attrTable != null) {
            Attribute attr = attrTable.get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.55"));
            if (attr != null) detectedExt = attr.getAttributeValues()[0].toString();
        }

        String res64 = "";
        if (sigData.getSignedContent() != null) {
            res64 = Base64.getEncoder().encodeToString((byte[]) sigData.getSignedContent().getContent());
        } else {
            res64 = (origData != null) ? origData.trim().replace("\"", "").replaceAll("\\s", "") : "";
        }

        log.info("end verify status: {}", isValid);
        return new VerifyResponse(isValid, res64, verCert.getSubjectDN().getName(), detectedExt);
    }


    public EncResponse encryptData(String pt) throws Exception {
        
        log.info("start enc");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);        
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher cipherAES = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        cipherAES.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        byte[] ct = cipherAES.doFinal(pt.getBytes(StandardCharsets.UTF_8));

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipherRSA.init(Cipher.ENCRYPT_MODE, pubkey);
        byte[] ctkey = cipherRSA.doFinal(aesKey.getEncoded());

        log.info("finish enc");
        
        return new EncResponse(
                Base64.getEncoder().encodeToString(ct),
                Base64.getEncoder().encodeToString(ctkey),
                Base64.getEncoder().encodeToString(iv)
        );
    }

    public String decryptData(String ct64, String ctkeyB64, String iv64) throws Exception {
        
        log.info("start dec");

        byte[] ct = Base64.getDecoder().decode(ct64);
        byte[] ctkey = Base64.getDecoder().decode(ctkeyB64);
        byte[] iv = Base64.getDecoder().decode(iv64);

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
        cipherRSA.init(Cipher.DECRYPT_MODE, privkey);
        byte[] keyB = cipherRSA.doFinal(ctkey);
        SecretKey key = new SecretKeySpec(keyB, "AES");

        Cipher cipherAES = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipherAES.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] data = cipherAES.doFinal(ct);

        return new String(data, StandardCharsets.UTF_8);
    }

    public String hashData(String input) throws Exception {
        
        log.info("hash");

        byte[] normInput = prepareData(input);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashB = digest.digest(normInput);
        return HexFormat.of().formatHex(hashB);
    }
}