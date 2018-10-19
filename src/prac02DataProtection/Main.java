package prac02DataProtection;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSALibrary rsaLibrary = new RSALibrary();
		String plainText = "modsfinosadvnoaknvoanpvaenrivrenaǜoinoaspndviojadsnpaskdnvlñsaknvñosdivnokasñboaniorenbijunvrijefvnksjdvnkdjvkdjviejr";
		//String to hold the name of the private key file.
		final String PRIVATE_KEY_FILE = "./private.key";

		 // String to hold name of the public key file.
		 final String PUBLIC_KEY_FILE = "./public.key";
		
		
		try {
			rsaLibrary.generateKeys();

			byte[] privateKeyBytes = Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE));

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

			FileInputStream filePublicKey = new FileInputStream(PUBLIC_KEY_FILE);
			ObjectInputStream oisPublicKey = new ObjectInputStream(filePublicKey);
			PublicKey publicKey = (PublicKey) oisPublicKey.readObject();
			System.out.println(publicKey);
			
			byte[] signature = rsaLibrary.sign(plainText.getBytes("UTF-8"), privateKey);
			System.out.println("Firma:");
			System.out.println(new String(signature));
			
			
			boolean verified = rsaLibrary.verify(plainText.getBytes("UTF-8"), signature, publicKey);
			System.out.println("Verficado:");
			System.out.println(verified);
			
			byte[] cipher = rsaLibrary.encrypt(plainText.getBytes("UTF-8"), publicKey);
			System.out.println(new String(cipher));

			byte[] newPlainText = rsaLibrary.decrypt(cipher, privateKey);
			System.out.println(new String(newPlainText));

			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
