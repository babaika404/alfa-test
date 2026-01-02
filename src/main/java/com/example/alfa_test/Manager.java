package com.example.alfa_test;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

@Slf4j
@Service
public class Manager {

    // можно по рофлу ебануть гост россия z
    // хзхз костыли 

    @Value("${app.ks.password}")
    private String kspass;

    @Value("${app.ks.alias}")
    private String ksalias;

    private PrivateKey privkey;
    private PublicKey pubkey;
    private X509Certificate cert;

    @PostConstruct
    public void init() throws Exception {

        log.info("key init");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = getClass().getResourceAsStream("/keystore.p12")) {
            ks.load(is, kspass.toCharArray());
        }
        this.privkey = (PrivateKey) ks.getKey(ksalias, kspass.toCharArray());
        this.cert = (X509Certificate) ks.getCertificate(ksalias);
        this.pubkey = cert.getPublicKey();
    }

    public String signData(String data) throws Exception {

        log.info("start sign");

        List<X509Certificate> certList = new ArrayList<>();
        certList.add(cert);
        JcaCertStore certs = new JcaCertStore(certList);

        CMSTypedData msg = new CMSProcessableByteArray(data.getBytes());
        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(privkey);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(sha256Signer, cert));
        gen.addCertificates(certs);

        CMSSignedData sigData = gen.generate(msg, true);
        return Base64.getEncoder().encodeToString(sigData.getEncoded());
    }

    public VerifyResponse verifyData(String sign64) throws Exception {

        log.info(" start verify");

        byte[] signB = Base64.getDecoder().decode(sign64);
        CMSSignedData signdata = new CMSSignedData(signB);

        SignerInformationStore signers = signdata.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        SignerInformation signer = c.iterator().next();

        X509CertificateHolder certHolder = (X509CertificateHolder) ((org.bouncycastle.util.Store) signdata.getCertificates())
                .getMatches(signer.getSID())
                .iterator().next();

        X509Certificate verifyCert = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(certHolder);

        boolean isValid = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(verifyCert));
        String originalContent = new String((byte[]) signdata.getSignedContent().getContent());

        return new VerifyResponse(isValid, originalContent, verifyCert.getSubjectDN().getName());
    }

    public EncResponse encryptData(String pt) throws Exception {
        
        log.info("start enc");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[16];
        SecureRandom secRand = new SecureRandom();
        secRand.nextBytes(iv);
        IvParameterSpec seciv = new IvParameterSpec(iv);


        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherAES.init(Cipher.ENCRYPT_MODE, aesKey, seciv);
        byte[] ct = cipherAES.doFinal(pt.getBytes());

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
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

        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipherRSA.init(Cipher.DECRYPT_MODE, privkey);
        byte[] keyB = cipherRSA.doFinal(ctkey);
        SecretKey key = new SecretKeySpec(keyB, 0, keyB.length, "AES");

        Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherAES.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] data = cipherAES.doFinal(ct);

        return new String(data);
    }
}