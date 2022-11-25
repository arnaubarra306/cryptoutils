package cat.uvic.teknos.m09.cryptoutils;

import cat.uvic.teknos.m09.cryptoutils.exceptions.NotAlogtirhmExc;
import cat.uvic.teknos.m09.cryptoutils.exceptions.NotKeyExc;
import cat.uvic.teknos.m09.cryptoutils.exceptions.PropExc;
import cat.uvic.teknos.m09.cryptoutils.models.Digest;

import java.io.IOException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
/**
 * @author arnau barra garcia
 * @author arnau.barra@uvic.cat
 */

public class CryptoUtils {
    private static Properties properties;

    static {
        try {
            properties=new Properties();
            properties.load(CryptoUtils.class.getResourceAsStream("/cryptoutils.properties"));
        } catch (IOException e) {
            throw new PropExc("Problem with the file please check its all correct");
        }
    }

    /***
     *
     * @param errorCode
     * @return hash return DigestRestult
     */
    public static Digest hash(byte[] errorCode)  {
        byte[] salt =null;
        Digest digestResult;

        String hashAlgorithm= (String) properties.get("hash.algorithm");
        boolean hashSalt=Boolean.parseBoolean((String) properties.get("hash.salt"));

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new NotAlogtirhmExc();
        }
        if(hashSalt) {
            salt = getSalt();
            messageDigest.update(salt);
        }
        var digest =messageDigest.digest(errorCode);
        if(hashSalt) {
            digestResult = new Digest(digest, hashAlgorithm);
        }else{
            digestResult = new Digest(digest, hashAlgorithm);
        }
        return digestResult;
    }

    /***
     *
     * @return Salt
     */
    private static byte[] getSalt(){
        var securerandom= new SecureRandom();
        var salt=new byte[16];
        securerandom.nextBytes(salt);
        return salt;
    }

    /***
     *
     * @return Propierties
     */
    public static Properties getProperties() {
        return properties;
    }

    /***
     *
     * @param plainText
     * @param password
     * @return encrypted password and plainText
     */
    public static byte[] encrypt(byte[] plainText, String password){
        var secretKey=getPrivateKeyFromPassword(password);
        var cipherAlgorithm=properties.getProperty("symmetric.cipherAlgorithm");
        try {
            var cipher = Cipher.getInstance(cipherAlgorithm);

            var ivStr=properties.getProperty("symmetric.encodedIvByteArr");
            byte[] decodedIvByteArr=Base64.getDecoder().decode(ivStr);

            var iv =new IvParameterSpec(decodedIvByteArr);


            cipher.init(Cipher.ENCRYPT_MODE,secretKey,iv);

            var cipherText = cipher.doFinal(plainText);

            return cipherText;
        } catch (NoSuchAlgorithmException e) {
            throw new NotAlogtirhmExc("Not good Alorithm");
        } catch (NoSuchPaddingException e) {
            throw new PropExc("Padding exception");
        } catch (InvalidAlgorithmParameterException e) {
            throw new NotAlogtirhmExc("Invalid algorith");
        } catch (InvalidKeyException e) {
            throw new NotKeyExc("Invalid detected or incorrect key");
        } catch (IllegalBlockSizeException e) {
            throw new PropExc("Illegal Block Size");
        } catch (BadPaddingException e) {
            throw new NotKeyExc("Not key detected or incorrect key");
        }


    }

    /***
     *
     * @param cipherText
     * @param password
     * @return decrypted text and password
     */
    public static byte[] decrypt(byte[] cipherText,String password){
        var secretKey=getPrivateKeyFromPassword(password);
        var cipherAlgorithm=properties.getProperty("symmetric.cipherAlgorithm");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(cipherAlgorithm);
            var ivStr=properties.getProperty("symmetric.encodedIvByteArr");
            byte[] decodedIvByteArr=Base64.getDecoder().decode(ivStr);
            var iv =new IvParameterSpec(decodedIvByteArr);

            cipher.init(Cipher.DECRYPT_MODE,secretKey,iv);

            var plainText=cipher.doFinal(cipherText);

            return plainText;
        } catch (NoSuchAlgorithmException e) {
            throw new NotAlogtirhmExc("Not good Alorithm");
        } catch (NoSuchPaddingException e) {
            throw new PropExc("Padding exception");
        } catch (InvalidAlgorithmParameterException e) {
            throw new NotAlogtirhmExc("Invalid algorith");
        } catch (InvalidKeyException e) {
            throw new NotKeyExc("Invalid detected or incorrect key");
        } catch (IllegalBlockSizeException e) {
            throw new PropExc("Illegal Block Size");
        } catch (BadPaddingException e) {
            throw new NotKeyExc("Not key detected or incorrect key");
        }
    }

    /***
     *
     * @param password
     * @return the private key from the password
     */
    private static Key getPrivateKeyFromPassword(String password){
        String saltStr=properties.getProperty("symmetric.secretKeySalt");

        byte[] salt= saltStr.getBytes();


        int iterationCount=Integer.parseInt(properties.getProperty("symmetric.iterations"));

        int keyLenght=Integer.parseInt(properties.getProperty("symmetric.keyLenght"));

        String secretKeyFactoryAlgorithm=properties.getProperty("symmetric.secretKeyFactoryAlgorithm");

        String secretKeySpecAlgorithm=properties.getProperty("symmetric.secretKeySpecAlgorithm");


        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLenght);
        SecretKey pbeKey = null;
        try {
            pbeKey = SecretKeyFactory.getInstance(secretKeyFactoryAlgorithm).generateSecret(pbeKeySpec);
            return new SecretKeySpec(pbeKey.getEncoded(), secretKeySpecAlgorithm);
        } catch (InvalidKeySpecException e) {
            throw new NotKeyExc("Invalid detected or incorrect key");
        } catch (NoSuchAlgorithmException e) {
            throw new NotAlogtirhmExc("Not good Alorithm");
        }
    }
}

