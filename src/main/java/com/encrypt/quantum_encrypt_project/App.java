package com.encrypt.quantum_encrypt_project;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import crypto.symmetric.ThreefishEncryptionService;

/**
 * Encrypt/Decrypt!
 *
 */
public class App {
	public static void main(String[] args) throws Exception {

		String symmetricKeyStoreName = "symmetric";
		String key = "pux";
		String word = "hello";

		System.out.println("encrypting word: " + word);

		System.out.println("----Using PQ symmetric Threefish 1024-Bit----");

		ThreefishEncryptionService threeFishService = new ThreefishEncryptionService();
		threeFishService.generateKeyStore(symmetricKeyStoreName, key);
		SecretKey secretKey = threeFishService.loadSecretKeyFromKeyStore(symmetricKeyStoreName + ".ubr", key);

		// byte [] data = new byte[20];
		byte[] data = word.getBytes(); // default StandardCharsets.UTF_8
		// new SecureRandom().nextBytes(data); // for random word
		ArrayList<byte[]> encryptedData = threeFishService.encrypt(secretKey, data);
		byte[] decryptedData = threeFishService.decrypt(secretKey, encryptedData.get(0), encryptedData.get(1));
		System.out.println("encrypted: " + new String(encryptedData.get(0)));
		System.out.println("decrypted: " + new String(decryptedData));

		System.out.println("----Using AES----");
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		SecretKey aesKey = keyGenerator.generateKey();
		String algorithm = "AES/CBC/PKCS5Padding";

		Cipher cipher = Cipher.getInstance(algorithm);
		// random Initialization Vector bytes
		// for 128 keygenerator  is mandatory 16 bytes
		byte[] ivBytes = new byte[16];
		new SecureRandom().nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
		byte[] cipherBytes = cipher.doFinal(word.getBytes());
		String cipherText = Base64.getEncoder().encodeToString(cipherBytes);

		cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
		byte[] plainBytes = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		String plainText = new String(plainBytes);

		System.out.println("encrypted: " + cipherText);
		System.out.println("decrypted: " + plainText);

	}
}
