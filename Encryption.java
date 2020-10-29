package com.sanfoundry.setandstring;

import static com.sanfoundry.setandstring.RSA.bytesToString;
import java.math.BigInteger;
import java.util.Random;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

class AES extends RSA {

    /**
     * gets the AES encryption key. In your actual programs, this should be safely
     * stored.
     * 
     * @return
     * @throws Exception
     */
    public static SecretKey getSecretEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        return secKey;
    }

    /**
     * Encrypts plainText in AES using the secret key
     * 
     * @param plainText
     * @param secKey
     * @return
     * @throws Exception
     */
    public static byte[] encryptText(String plainText, SecretKey secKey) throws Exception {
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return byteCipherText;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] hash) {
        char[] hexChars = new char[hash.length * 2];
        for (int j = 0; j < hash.length; j++) {
            int v = hash[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /*
     * protected static String bytesToHex(byte[] hash) { for (byte b : hash) {
     * String st = String.format("%02X", b); return st; } // return
     * DatatypeConverter.printHexBinary(hash); }
     */

    public static String decryptText(byte[] byteCipherText, SecretKey secKey) throws Exception {
        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(byteCipherText);
        return new String(bytePlainText);
    }

}

class RSA {

    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int bitlength = 1024;
    private Random r;

    public RSA() {
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 2, r);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
    }

    public RSA(BigInteger e, BigInteger d, BigInteger N) {
        this.e = e;
        this.d = d;
        this.N = N;
    }

    protected static String bytesToString(byte[] encrypted) {
        String test = "";
        for (byte b : encrypted) {
            test += Byte.toString(b);
        }
        return test;
    }

    // Encrypt message
    public byte[] encrypt(byte[] message) {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }

    // Decrypt message
    public byte[] decrypt(byte[] message) {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }

}

public class Encryption extends AES {
    public static void main(String[] args) throws Exception {

        System.out.println("enter text you want to encrypt");
        BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));
        String plainText = buffer.readLine();
        SecretKey secKey = getSecretEncryptionKey();
        byte[] cipherText = encryptText(plainText, secKey);
        // String decryptedText = decryptText(cipherText, secKey);
        System.out.println("\nOriginal Text: " + plainText + "\n");
        System.out.println("calculating the key for aes algorithm... \ncompleted!!!  \n");

        System.out.println("AES Key (Hex Form):" + bytesToHex(secKey.getEncoded()));
        System.out.println("\nencrypting text using the AES key generated... \n");
        System.out.println("Encrypted Text (Hex Form): " + bytesToHex(cipherText));
        // RSA
        RSA rsa = new RSA();
        // byte[] teststring;
        // teststring=cipherText;
        // encrypt
        byte[] encrypted = rsa.encrypt(cipherText);
        System.out.println("\nRSA encrypted AES key: " + encrypted + "\n");
        // decrypt
        byte[] decrypted = rsa.decrypt(encrypted);
        System.out.println("do you want to decrypt it and get the text back");
        System.out.println("press    1 for yes        2 for no");
        int yn = Integer.parseInt(buffer.readLine());
        System.out.println("\n");
        if (yn == 2) {
            System.out.println("thankyou you data got encrypted\n");
        } else {
            System.out.println("decrypting the key... \n\nRSA Decrypted KEY: " + bytesToString(decrypted));
            System.out.println("\nDecrypting the text using the KEY generated...\n");

            String decryptedText = decryptText(cipherText, secKey);
            System.out.println("Decrypted Text: " + decryptedText + "\n ");
        }
    }
}