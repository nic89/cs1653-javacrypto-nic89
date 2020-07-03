import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;


import java.nio.charset.StandardCharsets;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;

public class Bouncy {
	public static void main(String args[]) {
		Scanner sc = new Scanner(System.in); 
		System.out.println("Type in a string to encrypt: ");
        String plaintext = sc.nextLine();
        
		Bouncy bc = new Bouncy();
		AES aes = bc.new AES();
		aes.AESTest(plaintext);
		Blowfish bf = bc.new Blowfish();
		bf.BlowfishTest(plaintext);
		
		
		RSA myRSA = bc.new RSA();
		myRSA.rsaTest("pubkey", "privkey", plaintext);
		
		System.out.println("\n**********************************************\n" 
							+ "Starting 100 Random Strings Performance Test \n"
							+ "**********************************************\n");
		//GENERATE ARRAY OF RANDOM STRINGS
		String randomStrings[] = new String[100];
		
		for(int i =0; i<100; i++) {
			randomStrings[i] = generateRandomString(32);
		}
		long rsaBench = myRSA.rsaTest100("pubkey", "privkey", randomStrings);
		long aesBench = aes.AESTest100(randomStrings);
		long blowfishBench = bf.BlowfishTest100(randomStrings);
		System.out.println("\nRSA/AES Time to encrypt 100 strings (ms) : " + rsaBench + "/" + aesBench + " = " +( rsaBench/aesBench  ) );
		System.out.println("\nRSA/Blowfish Time to encrypt 100 strings (ms) : " + rsaBench + "/" + blowfishBench + " = " +( rsaBench/blowfishBench ));
		System.out.println("\nBlowfish/AES Time to encrypt 100 strings (ms) : " + blowfishBench + "/" + aesBench + " = " + (blowfishBench /aesBench ));
		
		
		
	}
	public static String generateRandomString(int byteLength) {
	    SecureRandom secureRandom = new SecureRandom();
	    byte[] token = new byte[byteLength];
	    secureRandom.nextBytes(token);
	    return new String(Base64.encode(token));
	}
	class AES{
	public String AESEncrypt(String plaintext, SecretKey key, PaddedBufferedBlockCipher cipher, ParametersWithIV keyParamWithIV) {
		try {	
    	
    	byte[] inputBytes = plaintext.getBytes("UTF-8");
    	int length;
		// Encrypt
        cipher.init(true, keyParamWithIV);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        length = cipher.processBytes(inputBytes,0,inputBytes.length, outputBytes, 0);
        cipher.doFinal(outputBytes, length); 
        String encryptedInput = new String(Base64.encode(outputBytes));
        return encryptedInput;
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return "";
		  }

	}
	public String AESDecrypt(String ciphertext, SecretKey key, PaddedBufferedBlockCipher cipher, ParametersWithIV keyParamWithIV) {
		try {
		
    	
		int length;
		//Decrypt            
        cipher.init(false, keyParamWithIV);
        byte[] out2 = Base64.decode(ciphertext);
        byte[] comparisonBytes = new byte[cipher.getOutputSize(out2.length)];
        length = cipher.processBytes(out2, 0, out2.length, comparisonBytes, 0);
        cipher.doFinal(comparisonBytes, length); //Do the final block
        String s2 = new String(comparisonBytes);
        return s2;
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return "";
		  }
	}
	
	
	public void AESTest(String plaintext) {
		try {
			
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

	        keyGenerator.init(128);
	        SecretKey key = keyGenerator.generateKey();
	        System.out.println("\nAES - Generated key (encoded in B64): " + Base64.encode(key.getEncoded()));
	      
	        byte[] iv = new byte[16]; // 128/8
	        Random r = new Random(); // Note: no  seed here, ie these values are truly random
	        r.nextBytes(iv);
	        System.out.println("\nAES - Generated IV (encoded in B64): " + new String(Base64.encode(iv)));
	        
	    	//engine setup
			AESEngine engine = new AESEngine();
			CBCBlockCipher blockCipher = new CBCBlockCipher(engine); 
			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); 
			KeyParameter keyParam = new KeyParameter(key.getEncoded());
			ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);
	        
			System.out.println("\nAES - Encrypting plaintext String:" + plaintext);
	    	String ciphertext = AESEncrypt(plaintext, key, cipher, keyParamWithIV);

	        
	        System.out.println("\nAES - Encrypted String (encodd in B64): " +ciphertext);
	        System.out.println("\nAES - Decrypted String: "+ AESDecrypt(ciphertext, key, cipher, keyParamWithIV));
	  
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		  }
	}
	public long AESTest100(String[] randomStrings) {
		try {
			
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

	        keyGenerator.init(128);
	        SecretKey key = keyGenerator.generateKey();
	        
	        byte[] iv = new byte[16]; // 128/8
	        Random r = new Random(); // Note: no  seed here, ie these values are truly random
	        r.nextBytes(iv);
	        
	    	//engine setup
			AESEngine engine = new AESEngine();
			CBCBlockCipher blockCipher = new CBCBlockCipher(engine); 
			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); 
			KeyParameter keyParam = new KeyParameter(key.getEncoded());
			ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);
	        
			
	    	
	    	//MEASURE AES
			long startTime = System.nanoTime();
			
			for(int i =0; i<100; i++) {
				AESEncrypt(randomStrings[i], key, cipher, keyParamWithIV);
			}
			long endTime = System.nanoTime();
			long duration = (endTime - startTime)/1000000;//milliseconds
	        return duration;
	        
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return (long)0;
		  }
	}
	
	}
	class Blowfish{
	public String BlowfishEncrypt(PaddedBufferedBlockCipher cipher, KeyParameter key, byte[] in) {
		try {	
			cipher.init(true, key);
			
			byte out[] = new byte[cipher.getOutputSize(in.length)];
			int len1 = cipher.processBytes(in, 0, in.length, out, 0);
			cipher.doFinal(out, len1);
			String s = new String(Base64.encode(out));
			return s;
    	
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return "";
		  }

	}
	public String BlowfishDecrypt(PaddedBufferedBlockCipher cipher, KeyParameter key, byte[] out) {
		try {
		cipher.init(false,  key);
		
		
		byte[] out2 = Base64.decode(out);
		byte decrypted[] = new byte[cipher.getOutputSize(out2.length)];
		int len2 = cipher.processBytes(out2, 0, out2.length, decrypted, 0);
		cipher.doFinal(decrypted, len2);
		
		
		String dec = new String(decrypted);
		return dec;
		}catch (Exception e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
			return "";
		}
	}
		  
	
	
	
	
	public void BlowfishTest(String input) {
		try {
			
			
				BlowfishEngine engine = new BlowfishEngine();
				PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				        engine);
				
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish", "BC");

				
				keyGenerator.init(128);
		        SecretKey key = keyGenerator.generateKey();
		        System.out.println("\nBlowfish - Generated Key (encoded in b64)" + Base64.encode(key.getEncoded()));
		        KeyParameter keyParam = new KeyParameter(key.getEncoded());
				byte in[] = input.getBytes();
				String ciphertext = BlowfishEncrypt(cipher, keyParam,in);
				System.out.println("\nBlowfish - Encrypted string (encoded in B64): " + new String(Base64.encode(ciphertext.getBytes())));
				String plain = BlowfishDecrypt(cipher, keyParam, ciphertext.getBytes());
				System.out.println("\nBlowfish - Decrypted string :" + plain);
			
			
			
			
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		  }
		
			
	}	
	
	public long BlowfishTest100(String[] randomStrings) {
		try {
			
			
				BlowfishEngine engine = new BlowfishEngine();
				PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				        engine);
				
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish", "BC");

				
				keyGenerator.init(128);
		        SecretKey key = keyGenerator.generateKey();
		        KeyParameter keyParam = new KeyParameter(key.getEncoded());
				
		      //MEASURE AES
				long startTime = System.nanoTime();
				
				for(int i =0; i<100; i++) {

			        byte in[] = randomStrings[i].getBytes();
					
					BlowfishEncrypt(cipher, keyParam,in);
				}
				long endTime = System.nanoTime();
				long duration = (endTime - startTime)/1000000;//milliseconds
		        return duration;
			
			
			
			
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return (long)0;
		  }
		
			
	}	
	}
	
	
	
	
	
	class RSA{
		public RSA() {}
		
		public void rsaTest(String pubKeyName, String privKeyName, String plaintext) {
			
			
			String keynames[] = new String[2];
			keynames[0] = pubKeyName;
			keynames[1] = privKeyName;
			System.out.println("\nGenerating RSA keys and storing them in files " + pubKeyName + " and " + privKeyName);
			generateRSAKeys(keynames);
			String encryptedrsa = RSAEncrypt(pubKeyName, plaintext, false);
			System.out.println("\nRSA encrypted using " + pubKeyName + ": " + encryptedrsa);
			String decryptedrsa = RSADecrypt(privKeyName, encryptedrsa, false);
			System.out.println("\nRSA decrypted using " + privKeyName + ": " + decryptedrsa);
			String signedrsa = RSAEncrypt(privKeyName, plaintext, true);
			System.out.println("\nRSA signed (encrypted using " + privKeyName + "): " + signedrsa);
			String verifiedrsa = RSADecrypt(pubKeyName, signedrsa, true);
			System.out.println("\nRSA verified (decrypted using " + pubKeyName + "): " + verifiedrsa);
		}
		
public long rsaTest100(String pubKeyName, String privKeyName, String[] randomStrings) {
			
			
			String keynames[] = new String[2];
			keynames[0] = pubKeyName;
			keynames[1] = privKeyName;
			generateRSAKeys(keynames);
			//MEASURE AES
			long startTime = System.nanoTime();
			
			for(int i =0; i<100; i++) {

				RSAEncrypt(pubKeyName, randomStrings[i], false);
			}
			long endTime = System.nanoTime();
			long duration = (endTime - startTime)/1000000;//milliseconds
	        return duration;
			
		}
		
	    public void generateRSAKeys(String args[])
	    {
	 
	        String publicKeyFilename = null;
	        String privateKeyFilename = null;
	 
	 
	        if (args.length < 2)
	        {
	            System.err.println("Usage: java "+ getClass().getName()+
	            " Public_Key_Filename Private_Key_Filename");
	            System.exit(1);
	        }
	 
	        publicKeyFilename = args[0].trim();
	        privateKeyFilename = args[1].trim();
	        generate(publicKeyFilename, privateKeyFilename);
	 
	    }
	 
	    private void generate (String publicKeyFilename, String privateFilename){
	 
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	 
	            // Create the public and private keys
	            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
	         
	 
	            SecureRandom random = createFixedRandom();
	            generator.initialize(1024, random);
	 
	            KeyPair pair = generator.generateKeyPair();
	            Key pubKey = pair.getPublic();
	            Key privKey = pair.getPrivate();
	           
	            System.out.println("\npublicKey : " + new String(java.util.Base64.getMimeEncoder().encode(pubKey.getEncoded()),
                        StandardCharsets.UTF_8));
	            System.out.println("\nprivateKey : " + new String(java.util.Base64.getMimeEncoder().encode(privKey.getEncoded()),
                        StandardCharsets.UTF_8));
	 
	            BufferedWriter out = new BufferedWriter(new FileWriter(publicKeyFilename));
	            out.write(new String(java.util.Base64.getMimeEncoder().encode(pubKey.getEncoded()),
                        StandardCharsets.UTF_8));
	            out.close();
	 
	            out = new BufferedWriter(new FileWriter(privateFilename));
	            out.write(new String(java.util.Base64.getMimeEncoder().encode(privKey.getEncoded()),
                        StandardCharsets.UTF_8));
	            out.close();
	 
	 
	        }
	        catch (Exception e) {
	            System.out.println(e);
	        }
	    }
	 
	    public SecureRandom createFixedRandom()
	    {
	        return new FixedRand();
	    }
	 
	    private class FixedRand extends SecureRandom {
	 
	        MessageDigest sha;
	        byte[] state;
	 
	        FixedRand() {
	            try
	            {
	                this.sha = MessageDigest.getInstance("SHA-1");
	                this.state = sha.digest();
	            }
	            catch (NoSuchAlgorithmException e)
	            {
	                throw new RuntimeException("can't find SHA-1!");
	            }
	        }
	 
	        public void nextBytes(byte[] bytes){
	 
	            int    off = 0;
	 
	            sha.update(state);
	 
	            while (off < bytes.length)
	            {                
	                state = sha.digest();
	 
	                if (bytes.length - off > state.length)
	                {
	                    System.arraycopy(state, 0, bytes, off, state.length);
	                }
	                else
	                {
	                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
	                }
	 
	                off += state.length;
	 
	                sha.update(state);
	            }
	        }
	    }
	 
	    
	    private String RSAEncrypt (String publicKeyFilename, String inputData, boolean rsaSign){
			 
	        String encryptedData = null;
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	 
	            String key = readFileAsString(publicKeyFilename);
	            
	            AsymmetricKeyParameter encryptionKey;
	            if(rsaSign) {
	            	encryptionKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decode(key));
	            } else {
	            	encryptionKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decode(key));
	            }
	            
	            
	            AsymmetricBlockCipher e = new RSAEngine();
	            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
	            e.init(true, encryptionKey);
	 
	            byte[] messageBytes = inputData.getBytes();
	            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
	 
	            
	            
	            encryptedData = getHexString(hexEncodedCipher);
	    
	        }
	        catch (Exception e) {
	            System.out.println(e);
	            e.printStackTrace();
	        }
	        
	        return encryptedData;
	    }
		
		private String RSADecrypt (String privateKeyFilename, String encryptedData, boolean rsaSign) {
			 
	        String outputData = null;
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	 
	            String key = readFileAsString(privateKeyFilename);
	            
	            AsymmetricKeyParameter decryptionKey;
	            if(rsaSign) {
	            	decryptionKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decode(key));
	            } else {
	            	decryptionKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decode(key));
	            }
	            
	            AsymmetricBlockCipher e = new RSAEngine();
	            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
	            e.init(false, decryptionKey);
	 
	            byte[] messageBytes = hexStringToByteArray(encryptedData);
	            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
	 
	            
	            outputData = new String(hexEncodedCipher);
	 
	        }
	        catch (Exception e) {
	        	e.printStackTrace();
	            System.out.println(e);
	            return "";
	        }
	        
	        return outputData;
	    }
		
		public String getHexString(byte[] b) throws Exception {
	        String result = "";
	        for (int i=0; i < b.length; i++) {
	            result +=
	                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
	        }
	        return result;
	    }
		
		public byte[] hexStringToByteArray(String s) {
	        int len = s.length();
	        byte[] data = new byte[len / 2];
	        for (int i = 0; i < len; i += 2) {
	            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                    + Character.digit(s.charAt(i+1), 16));
	        }
	        return data;
	    }
	 
	    private String readFileAsString(String filePath) throws java.io.IOException{
	        StringBuffer fileData = new StringBuffer(1000);
	        BufferedReader reader = new BufferedReader(
	                new FileReader(filePath));
	        char[] buf = new char[1024];
	        int numRead=0;
	        while((numRead=reader.read(buf)) != -1){
	            String readData = String.valueOf(buf, 0, numRead);
	            fileData.append(readData);
	            buf = new char[1024];
	        }
	        reader.close();
	        return fileData.toString();
	    }
	    
	}
}
