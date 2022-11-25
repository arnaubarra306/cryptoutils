package cat.uvic.teknos.m09.cryptoutils.models;

public class Digest {
    private byte[] hash;
    private byte[] salt;
    private String algorithm;

    public Digest(byte[] hash, String algorithm) {
        this.hash = hash;
        this.salt = null;
        this.algorithm = algorithm;
    }

    public byte[] getHash() {
        return hash;
    }
    public byte[] getSalt() {
        return salt;
    }

    public String getAlgorithm() {
        return algorithm;
    }

}