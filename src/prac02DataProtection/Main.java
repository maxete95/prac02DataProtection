package prac02DataProtection;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSALibrary rsaLibrary = new RSALibrary();
		String plainText = "hola";
		//String to hold the name of the private key file.
		final String PRIVATE_KEY_FILE = "./private.key";

		 // String to hold name of the public key file.
		 final String PUBLIC_KEY_FILE = "./public.key";
		
		
		try {
			rsaLibrary.generateKeys();
			
			FileInputStream keyfis = new FileInputStream(PUBLIC_KEY_FILE);
			byte[] encKey = new byte[keyfis.available()];  
			keyfis.read(encKey);
			
			FileInputStream keyfis2 = new FileInputStream(PRIVATE_KEY_FILE);
			byte[] encKey2 = new byte[keyfis2.available()];  
			keyfis2.read(encKey2);
			
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
			System.out.println(publicKey);
			
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encKey2);
			KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(spec);
			
			byte[] signature = rsaLibrary.sign(plainText.getBytes("UTF-8"), privateKey);
			System.out.println("Firma:");
			System.out.println(new String(signature));
			
			
			boolean verified = rsaLibrary.verify(plainText.getBytes("UTF-8"), signature, publicKey);
			System.out.println("Verficado:");
			System.out.println(verified);
			
			byte[] cipher = rsaLibrary.encrypt(plainText.getBytes("UTF-8"), publicKey);
			System.out.println(cipher);
			
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
