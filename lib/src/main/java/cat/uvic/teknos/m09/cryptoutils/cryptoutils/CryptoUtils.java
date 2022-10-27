package cat.uvic.teknos.m09.cryptoutils.cryptoutils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

public class CryptoUtils {
    public static String getHash(byte[] message) throws IOException, NoSuchAlgorithmException {
        var fmessage = "";
        var properties = new Properties();

        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        var hashAlgorithm = properties.getProperty("hash.algorithm");
        boolean salt = Boolean.parseBoolean((String) properties.get("hash.salt"));

        if (salt) {
            var salt1 = getSalt();
            fmessage = getDigest(message, salt1, hashAlgorithm);

        } else {
            fmessage = getDigestNoSalt(message, hashAlgorithm);
        }
        return fmessage;
    }
    private static String getDigestNoSalt(byte[] data, String algorithm) throws NoSuchAlgorithmException {
        var messageDigest = MessageDigest.getInstance(algorithm);

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }
    private static String getDigest(byte[] data, byte[] salt, String algorithm) throws NoSuchAlgorithmException {
        var messageDigest = MessageDigest.getInstance(algorithm);

        messageDigest.update(salt);

        var digest = messageDigest.digest(data);

        var base64Encoder = Base64.getEncoder();

        return base64Encoder.encodeToString(digest);
    }

    private static byte[] getSalt() {
        var secureRandom = new SecureRandom();

        var salt = new byte[15];
        secureRandom.nextBytes(salt);

        return salt;
    }
    public static byte[] encrypt(byte[] plainText, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        var iv = new IvParameterSpec(properties.getProperty("hash.iv").getBytes());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), getSalt(), Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);

        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");

        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(plainText);
    }
    public static byte[] decrypt(byte[] cipherText, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();
        properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));

        var iv = new IvParameterSpec(properties.getProperty("hash.iv").getBytes());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), getSalt(), Integer.parseInt(properties.getProperty("hash.iterations")), 256);
        SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);

        var secretKey =  new SecretKeySpec(pbeKey.getEncoded(), "AES");

        var cipher = Cipher.getInstance(properties.getProperty("hash.symmetricAlgorithm"));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher.doFinal(cipherText);
    }
    public static byte[] sing () {
        var message = Files.readAllBytes(Paths.get("app/src/main/resources/message.txt"));

        var keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("app/src/main/resources/m09.p12"), "Arnau03.".toCharArray());
        var privateKey = keystore.getKey("self_signed_ca", "Arnau03.".toCharArray());

        var signer = Signature.getInstance("SHA256withRSA");
        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        var signature = signer.sign();

        var base64Encoder = Base64.getEncoder();
        var cipherTextBase64 = base64Encoder.encodeToString(signature);

        System.out.println("Signature: " +  base64Encoder.encodeToString(signature));
    }

    public static byte[] verify () {
        var certificateFactory = CertificateFactory.getInstance("X.509");
        var certificate = certificateFactory.generateCertificate(new FileInputStream("app/src/main/resources/certificate.cer"));
        try {
            ((X509Certificate) certificate).checkValidity();
        } catch( Exception e) {
            System.out.println(e.getMessage());
        }
        var publicKey = certificate.getPublicKey();

        signer.initVerify(publicKey);
        signer.update(message);

        var isValid = signer.verify(signature);

        System.out.println("Signature is valid: " + isValid);
    }
    public static void main(String[] args) {
        byte[] myvar = "Any String you want".getBytes();
        try {
            System.out.println(getHash(myvar));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }


    }
    @Test void When_Hash1SameAlgorithmAndNoSaltAsHash2_Expect_Hash1EqualsHash2AsTrue() {
        synchronized (CryptoUtils.class) {
            CryptoUtils.getProperties().setProperty("hash.algorithm","SHA-256");
            CryptoUtils.getProperties().setProperty("hash.salt","false");
            var message = "message";
            var digestResult1 = CryptoUtils.hash(message.getBytes());
            var digestResult2=CryptoUtils.hash(message.getBytes());
            assertTrue(Arrays.equals(digestResult1.getHash(),digestResult2.getHash()));
        }
}
