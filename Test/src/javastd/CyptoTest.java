package javastd;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class PrintBytes{
	public static void printHexString(byte[] b){
		
	    for (int i = 0; i < b.length; i++){
	            String hex = Integer.toHexString(b[i] & 0xFF);
	            if (hex.length() == 1)
	            {
	                hex = '0' + hex;
	            }
	            System.out.print(hex.toUpperCase() + " ");
	        }
	        System.out.println("");
	}
}

class Base64Test{
	public static void test(){
		byte[] bytes=new byte[]{1,2,3};
		System.out.println(new String(Base64.getEncoder().encode(bytes)));
	}
}

class MessageDiestTest{
	//private static final String PLAIN_TEXT = "ZEASN2016:1c5a6bfffeafbbcb:https://deviceportal.nettvservices.com/dp/route";//"i m a sample";
	//private static final String PLAIN_TEXT = "r7wPMdgGatmJPhnfgGbQn0wTyDk=DFL0H2dx";//"i m a sample";
	private static final String PLAIN_TEXT = "abc:wudy:123:456:/alpha/httpdigest-authz-server";//"i m a sample";
	private static final String MD_ALGORITHM = "MD5";
	private static final String SHA_ALGORITHM_1 = "SHA-1";
	private static final String SHA_ALGORITHM_256 = "SHA-256";
	private static final String SHA_ALGORITHM_512 = "SHA-512";
	private static final String MAC_ALGORITHM_256 = "HmacSHA256";
	private static final String MAC_ALGORITHM_512 = "HmacSHA512";
	
	private static final String SECRET_KEY="123456";
	
	public static void test() {
		System.out.println("HttpDigestAuthz->response: start");
		HttpDigestAuthzResponse();
		System.out.println("HttpDigestAuthz->response: end");
		System.out.println("MD5: " + MD5(PLAIN_TEXT.getBytes()));
		System.out.println("SHA-1: " + SHA(PLAIN_TEXT.getBytes(),SHA_ALGORITHM_1));
		System.out.println("SHA-256: " + SHA(PLAIN_TEXT.getBytes(),SHA_ALGORITHM_256));
		System.out.println("SHA-512: " + SHA(PLAIN_TEXT.getBytes(),SHA_ALGORITHM_512));
		System.out.println("HmacSHA256��" + MAC(PLAIN_TEXT.getBytes(),MAC_ALGORITHM_256));
		System.out.println("HmacSHA512��" + MAC(PLAIN_TEXT.getBytes(),MAC_ALGORITHM_512));
	}
	
	/**
	 *  ascii ת��
	 */
	public static void Hex2Ascii(
		    byte[] Bin,
		    byte[] Hex
		    )
		{
		     short i;
		     char j;

		    for (i = 0; i < Bin.length; i++) {
		        j = (char) ((Bin[i] >> 4) & 0xf);
		        if (j <= 9)
		            Hex[i*2] = (byte) (j + '0');
		         else
		            Hex[i*2] = (byte) (j + 'a' - 10);
		        j = (char) (Bin[i] & 0xf);
		        if (j <= 9)
		            Hex[i*2+1] = (byte) (j + '0');
		         else
		            Hex[i*2+1] = (byte) (j + 'a' - 10);
		    };
		    //Hex[Hex.length] = '\0';
		};
		
	/**
	 * calculate http digest authz response
	 * MD5(Hex2Ascii(MD5(username:realm:password)):nonce:Hex2Ascii(MD5(method:uri)))
	 */
	public static void 	HttpDigestAuthzResponse(){
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(MD_ALGORITHM);
			final byte[] byte1="abc:wudy:123".getBytes();			
			String str2=":456:";
			final byte[] byte3="GET:/alpha/httpdigest-authz-server".getBytes();
			
			byte[] Ha1_temp=messageDigest.digest(byte1);
			byte[] Ha1=new byte[Ha1_temp.length*2];
			Hex2Ascii(Ha1_temp,Ha1);
			//PrintBytes.printHexString(Ha1);
			byte[] Ha2=str2.getBytes();
			//PrintBytes.printHexString(Ha2);
			byte[] Ha3_temp=messageDigest.digest(byte3);
			byte[] Ha3=new byte[Ha3_temp.length*2];
			Hex2Ascii(Ha3_temp,Ha3);
			//PrintBytes.printHexString(Ha3);
			byte[] HAll=new byte[Ha1.length+Ha2.length+Ha3.length];
			System.arraycopy(Ha1, 0, HAll, 0, Ha1.length); 
			System.arraycopy(Ha2, 0, HAll, Ha1.length, Ha2.length); 
			System.arraycopy(Ha3, 0, HAll, Ha1.length+Ha2.length, Ha3.length); 
			//PrintBytes.printHexString(HAll);
			PrintBytes.printHexString(messageDigest.digest(HAll));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

    /**
     * 1.��ϢժҪ�㷨��MD���壬��MD2 MD4 MD5������MD4 JDK��֧��
     * 
     * @param plainText
     * @return
     */
	public static String MD5(byte[] plainText) {
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(MD_ALGORITHM);			
			//PrintBytes.printHexString(messageDigest.digest(plainText));
			//return new String(messageDigest.digest(plainText));
			return Base64.getEncoder().encodeToString(messageDigest.digest(plainText));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;		
	}
	
    /**
     * 2.SHA Security Hash Algorithm ��ȫɢ���㷨���̶�����ժҪ��Ϣ SHA-1 SHA-2( SHA-224
     * SHA-256 SHA-384 SHA-512) ʹ�õ���Ȼ��MessageDigest�࣬JDK��֧��224
     * 
     * @param plainText
     * @return
     */
    public static String SHA(byte[] plainText,String alg) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(alg);
            //PrintBytes.printHexString(messageDigest.digest(plainText));
            return Base64.getEncoder().encodeToString(messageDigest.digest(plainText));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    /**
     * 3.MAC(Message Authentication Code) ��Ϣ��֤���㷨���Ǻ�����Կɢ�к����㷨��
     * ������MD��SHA�����ԡ�
     * ���ܹ��������ߣ������Ҫ���ܵĶԳƼ��ܺͷǶԳƼ��������Ƶ�
     * 1) �����㷨��ʵ����һ��������
     * 2) ������Կ����ʼ��������
     * 3) ����doFinal�������м���
     * @param plainText
     * @return
     * @throws InvalidKeyException 
     */
    public static String MAC(byte[] plainText,String alg) {

        try {
            //byte[] secretBytes = generatorMACSecretKey(alg);
        	byte[] secretBytes = SECRET_KEY.getBytes();
            SecretKey key = restoreMACSecretKey(secretBytes,alg);
            Mac mac = Mac.getInstance(alg);
            mac.init(key);
            return Base64.getEncoder().encodeToString(mac.doFinal(plainText));
        } catch (NoSuchAlgorithmException|InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    /**
     * MAC���������Կ ������ 1.����һ��KeyGenerator 2.����KeyGenerator.generateKey����
     * 
     * @return
     */
    public static byte[] generatorMACSecretKey(String alg) {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(alg);
            SecretKey key = keyGenerator.generateKey();
            return key.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ��ԭ��Կ
     * 
     * @param secretBytes
     * @return
     */
    public static SecretKey restoreMACSecretKey(byte[] secretBytes,String alg) {
        SecretKey key = new SecretKeySpec(secretBytes, alg);
        return key;
    }
}

class AesTest{

	    /**
	     * ע��key�ͼ����õ����ַ����ǲ�һ���� ���ܻ�Ҫָ�����ļ���ģʽ�����ģʽ AES��Կ������128����256������ģʽ����ECB, CBC��
	     * ECBģʽ�Ƿ����ģʽ��CBC�Ƿֿ���ܺ�ÿ����ǰһ��ļ��ܽ�������ټ��� ��һ����ܵ���������IV�����������
	     */
	    private static final String KEY_ALGORITHM = "AES";
	    private static final String ECB_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
	    private static final String CBC_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	    private static final String PLAIN_TEXT = "MANUTD is the greatest club in the world";

	    /**
	     * IV(Initialization Value)��һ����ʼֵ������CBCģʽ��˵�������������ѡȡ������Ҫ���ܵ�
	     * �������ĳ��Ⱥ����������ͬ(���磺����AES 128Ϊ128λ��������Ϊ16��byte��������)
	     * 
	     */
	    private static final byte[] IVPARAMETERS = new byte[] { 1, 2, 3, 4, 5, 6, 7,
	            8, 9, 10, 11, 12, 13, 14, 15, 16 };

	    public static void test() {
	        //byte[] secretBytes = generateAESSecretKey();
	        //System.out.println("secretBytes.length="+secretBytes.length);
	    	byte[] secretBytes = new byte[16];
	    	int i;
	    	for(i=0;i<16;i++)
	    		secretBytes[i]=(byte) i;
	        SecretKey key = restoreSecretKey(secretBytes);
	        byte[] encodedText = AesEcbEncode(PLAIN_TEXT.getBytes(), key);
	        PrintBytes.printHexString(encodedText);

	        System.out.println("AES ECB encoded with Base64: " + Base64.getEncoder().encodeToString(encodedText));
	        System.out.println("AES ECB decoded: "
	                + AesEcbDecode(encodedText, key));

	        
	        
	        encodedText = AesCbcEncode(PLAIN_TEXT.getBytes(), key, IVPARAMETERS);
	        
	        
	        System.out.println("AES CBC encoded with Base64: " + Base64.getEncoder().encodeToString(encodedText));
	        System.out.println("AES CBC decoded: "
	                + AesCbcDecode(encodedText, key,
	                        IVPARAMETERS));
	    }

	    /**
	     * ʹ��ECBģʽ���м��ܡ� ���ܹ��������ߣ� 1. �����㷨��ʵ����һ���ӽ����� 2. �������ģʽ����Կ����ʼ��һ�������� 3.
	     * ����doFinal��������
	     * 
	     * @param plainText
	     * @return
	     */
	    public static byte[] AesEcbEncode(byte[] plainText, SecretKey key) {

	        try {

	            Cipher cipher = Cipher.getInstance(ECB_CIPHER_ALGORITHM);
	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            return cipher.doFinal(plainText);
	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	        return null;
	    }

	    /**
	     * ʹ��ECB���ܣ������ߣ���˵��
	     * 
	     * @param decodedText
	     * @param key
	     * @return
	     */
	    public static String AesEcbDecode(byte[] decodedText, SecretKey key) {
	        try {
	            Cipher cipher = Cipher.getInstance(ECB_CIPHER_ALGORITHM);
	            cipher.init(Cipher.DECRYPT_MODE, key);
	            return new String(cipher.doFinal(decodedText));
	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	        return null;

	    }

	    /**
	     * CBC���ܣ������ߣ�ֻ���ڳ�ʼ��ʱ����һ����ʼ����
	     * 
	     * @param plainText
	     * @param key
	     * @param IVParameter
	     * @return
	     */
	    public static byte[] AesCbcEncode(byte[] plainText, SecretKey key,
	            byte[] IVParameter) {
	        try {
	            IvParameterSpec ivParameterSpec = new IvParameterSpec(IVParameter);

	            Cipher cipher = Cipher.getInstance(CBC_CIPHER_ALGORITHM);
	            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
	            return cipher.doFinal(plainText);

	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	        return null;
	    }

	    /**
	     * CBC ����
	     * 
	     * @param decodedText
	     * @param key
	     * @param IVParameter
	     * @return
	     */
	    public static String AesCbcDecode(byte[] decodedText, SecretKey key,
	            byte[] IVParameter) {
	        IvParameterSpec ivParameterSpec = new IvParameterSpec(IVParameter);

	        try {
	            Cipher cipher = Cipher.getInstance(CBC_CIPHER_ALGORITHM);
	            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
	            return new String(cipher.doFinal(decodedText));
	        } catch (Exception e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }

	        return null;

	    }

	    /**
	     * 1.����һ��KeyGenerator 2.����KeyGenerator.generateKey����
	     * ����ĳЩԭ������ֻ����128���������Ϊ256�ᱨ�쳣��ԭ������������˵��
	     * 
	     * @return
	     */
	    public static byte[] generateAESSecretKey() {
	        KeyGenerator keyGenerator;
	        try {
	            keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
	            // keyGenerator.init(256);
	            return keyGenerator.generateKey().getEncoded();
	        } catch (NoSuchAlgorithmException e) {
	            // TODO Auto-generated catch block
	            e.printStackTrace();
	        }
	        return null;
	    }

	    /**
	     * ��ԭ��Կ
	     * 
	     * @param secretBytes
	     * @return
	     */
	    public static SecretKey restoreSecretKey(byte[] secretBytes) {
	        SecretKey secretKey = new SecretKeySpec(secretBytes, KEY_ALGORITHM);
	        return secretKey;
	    }
}

class RsaCyptoTest{
    public static final String KEY_ALGORITHM = "RSA";
    /** ò��Ĭ����RSA/NONE/PKCS1Padding��δ��֤ */
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";

    /** RSA��Կ���ȱ�����64�ı�������512~65536֮�䡣Ĭ����1024 */
    public static final int KEY_SIZE = 2048;

    public static final String PLAIN_TEXT = "MANUTD is the greatest club in the world";

    public static void test() {
        Map<String, byte[]> keyMap = generateKeyBytes();

        // ����
        PublicKey publicKey = restorePublicKey(keyMap.get(PUBLIC_KEY));
   
        byte[] encodedText = RSAEncode(publicKey, PLAIN_TEXT.getBytes());
        System.out.println("RSA encoded: " + Base64.getEncoder().encodeToString(encodedText));

        // ����
        PrivateKey privateKey = restorePrivateKey(keyMap.get(PRIVATE_KEY));
        System.out.println("RSA decoded: "
                + RSADecode(privateKey, encodedText));
    }

    /**
     * ������Կ�ԡ�ע��������������Կ��KeyPair��������Կ�Ի�ȡ��˽Կ
     * 
     * @return
     */
    public static Map<String, byte[]> generateKeyBytes() {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance(KEY_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            Map<String, byte[]> keyMap = new HashMap<String, byte[]>();
            keyMap.put(PUBLIC_KEY, publicKey.getEncoded());
            keyMap.put(PRIVATE_KEY, privateKey.getEncoded());
            return keyMap;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ��ԭ��Կ��X509EncodedKeySpec ���ڹ�����Կ�Ĺ淶
     * 
     * @param keyBytes
     * @return
     */
    public static PublicKey restorePublicKey(byte[] keyBytes) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);

        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);
            return publicKey;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ��ԭ˽Կ��PKCS8EncodedKeySpec ���ڹ���˽Կ�Ĺ淶
     * 
     * @param keyBytes
     * @return
     */
    public static PrivateKey restorePrivateKey(byte[] keyBytes) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                keyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey privateKey = factory
                    .generatePrivate(pkcs8EncodedKeySpec);
            return privateKey;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ���ܣ������ߡ�
     * 
     * @param publicKey
     * @param plainText
     * @return
     */
    public static byte[] RSAEncode(PublicKey publicKey, byte[] plainText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(plainText);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    /**
     * ���ܣ������ߡ�
     * 
     * @param privateKey
     * @param encodedText
     * @return
     */
    public static String RSADecode(PrivateKey privateKey, byte[] encodedText) {

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(encodedText));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }
}


/**
 * RSA����ǩ��������RsaCyptoTest�е��㷨�������ظ�
 * ����ǩ����ѭ��˽Կǩ������Կ��ǩ��ԭ����Ϊ˽Կ�Ǹ��������֤
 * @author Kinsley
 *
 */
class SignatureTest {
    
    /** ����ǩ���㷨��JDKֻ�ṩ��MD2withRSA, MD5withRSA, SHA1withRSA���������㷨��Ҫ������������֧�� */
    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    
    public static final String PLAIN_TEXT = "MANUTD is the greatest club in the world";
    public static void test()
    {
        //�������׹�˽Կ��
        Map<String, byte[]> keyMapA = RsaCyptoTest.generateKeyBytes();
        PublicKey publicKeyA = RsaCyptoTest.restorePublicKey(keyMapA.get(RsaCyptoTest.PUBLIC_KEY));
        PrivateKey privateKeyA = RsaCyptoTest.restorePrivateKey(keyMapA.get(RsaCyptoTest.PRIVATE_KEY));
        
        Map<String, byte[]> keyMapB = RsaCyptoTest.generateKeyBytes();
        PublicKey publicKeyB =RsaCyptoTest.restorePublicKey(keyMapB.get(RsaCyptoTest.PUBLIC_KEY));
        PrivateKey privateKeyB =RsaCyptoTest.restorePrivateKey(keyMapB.get(RsaCyptoTest.PRIVATE_KEY));
        
        /** ��������Aǩ������B������Ϣ
         * A��B�Ĺ�Կ���м���
         * ���Լ�A��˽Կ����ǩ��
         */
        byte[] encodedText = RsaCyptoTest.RSAEncode(publicKeyB, PLAIN_TEXT.getBytes());
        byte[] signature = sign(privateKeyA, PLAIN_TEXT.getBytes());
        
        /**
         * ����B�յ���A����Ϣ��������������
         * ��B��˽Կ���ܵõ�����
         * �����ĺ�A�Ĺ�Կ������ǩ����
         */
        
        byte[] decodedText = RsaCyptoTest.RSADecode(privateKeyB, encodedText).getBytes();
        System.out.println("Decoded Text: " + new String(decodedText));
        
        System.out.println("Signature is " + verify(publicKeyA, signature, decodedText));
    }
    
    /**
     * ǩ����������
     * 1. ʵ�����������㷨
     * 2. ��ʼ��������˽Կ
     * 3. ǩ��
     * @param key
     * @param plainText
     * @return
     */
    public static byte[] sign(PrivateKey privateKey, byte[] plainText)
    {
        try {
            //ʵ����
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            
            //��ʼ��������˽Կ
            signature.initSign(privateKey);
            
            //����
            signature.update(plainText);
            
            //ǩ��
            return signature.sign();
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return null;
    }
    
    /**
     * ��ǩ��������
     * 1. ʵ�����������㷨
     * 2. ��ʼ�������빫Կ
     * 3. ��ǩ
     * @param publicKey
     * @param signatureVerify
     * @param plainText
     * @return
     */
    public static boolean verify(PublicKey publicKey, byte[] signatureVerify, byte[] plainText )
    {
        try {
            //ʵ����
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            
            //��ʼ��
            signature.initVerify(publicKey);
            
            //����
            signature.update(plainText);
            
            //��ǩ
            return signature.verify(signatureVerify);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return false;
    }
}

/** 1.������ǩ��֤��
 * 	keytool -genkeypair -keyalg RSA -keysize 2048 -sigalg SHA1withRSA -validity 3600 -alias myCertificate -keystore myKeystore.keystore
 * 2.����֤��
 * 	keytool -exportcert -alias myCertificate -keystore myKeystore.keystore -file myCer.cer -rfc
 * 3.����ǩ������
 * keytool -certreq -alias myCertificate -keystore myKeystore.keystore -file myCsr.csr -v
 * 4.����֤��
 * keytool -importcert -trustcacerts -alias myCertificate -file myCer.cer -keystore myKeystore.keystore
 * 5.�鿴֤��
 * keytool -list -alias myCertificate -keystore myKeystore.keystore
 */
class CertifacateTest {
    private static final String STORE_PASS = "123456";
    private static final String ALIAS = "myCertificate";
    private static final String KEYSTORE_PATH = "F:\\eclipse\\workspace\\CertTestPath\\myKeystore.keystore";
    private static final String CERT_PATH = "F:\\eclipse\\workspace\\CertTestPath\\myCer.cer";
    private static final String PLAIN_TEXT = "MANUTD is the most greatest club in the world.";
    /** JDK6ֻ֧��X.509��׼��֤�� */
    private static final String CERT_TYPE = "X.509";

    public static void test() throws IOException {
        /**
         * ��������������һ������ ��A�����ϵ����ݣ���Ҫ���ܵ�����Ȼ�󽫵����ļ��ŵ�B�����ϵ��롣 ����������У�A�൱�ڷ�������B�൱�ڿͻ���
         */

        /** A */
        KeyStore keyStore = getKeyStore(STORE_PASS, KEYSTORE_PATH);
        PrivateKey privateKey = getPrivateKey(keyStore, ALIAS, STORE_PASS);
        X509Certificate certificate = getCertificateByKeystore(keyStore, ALIAS);

        /** ���ܺ�ǩ�� */
        byte[] encodedText = encode(PLAIN_TEXT.getBytes(), privateKey);
        byte[] signature = sign(certificate, privateKey, PLAIN_TEXT.getBytes());

        /** ����B�յ���A�����ĺ�ǩ�����Լ�A�Ŀ�����֤�� */
        X509Certificate receivedCertificate = getCertificateByCertPath(
                CERT_PATH, CERT_TYPE);
        PublicKey publicKey = getPublicKey(receivedCertificate);
        byte[] decodedText = decode(encodedText, publicKey);
        System.out.println("Decoded Text : " + new String(decodedText));
        System.out.println("Signature is : "
                + verify(receivedCertificate, decodedText, signature));
    }

    /**
     * ������Կ�⣬��Properties�ļ��ļ������ƣ�����ʹ��load����
     * 
     * @throws IOException
     */
    public static KeyStore getKeyStore(String storepass, String keystorePath)
            throws IOException {
        InputStream inputStream = null;
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            inputStream = new FileInputStream(keystorePath);
            keyStore.load(inputStream, storepass.toCharArray());
            return keyStore;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (null != inputStream) {
                inputStream.close();
            }
        }
        return null;
    }

    /**
     * ��ȡ˽Կ
     * 
     * @param keyStore
     * @param alias
     * @param password
     * @return
     */
    public static PrivateKey getPrivateKey(KeyStore keyStore, String alias,
            String password) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ��ȡ��Կ
     * 
     * @param certificate
     * @return
     */
    public static PublicKey getPublicKey(Certificate certificate) {
        return certificate.getPublicKey();
    }

    /**
     * ͨ����Կ���ȡ����֤�飬����Ҫ���룬��Ϊ��ȡ��Keystoreʵ��
     * 
     * @param keyStore
     * @param alias
     * @return
     */
    public static X509Certificate getCertificateByKeystore(KeyStore keyStore,
            String alias) {
        try {
            return (X509Certificate) keyStore.getCertificate(alias);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    /**
     * ͨ��֤��·������֤�飬�������Կ���࣬��Ҫ�õ�����
     * 
     * @param path
     * @param certType
     * @return
     * @throws IOException
     */
    public static X509Certificate getCertificateByCertPath(String path,
            String certType) throws IOException {
        InputStream inputStream = null;
        try {
            // ʵ����֤�鹤��
            CertificateFactory factory = CertificateFactory
                    .getInstance(certType);
            // ȡ��֤���ļ���
            inputStream = new FileInputStream(path);
            // ����֤��
            Certificate certificate = factory.generateCertificate(inputStream);

            return (X509Certificate) certificate;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (null != inputStream) {
                inputStream.close();
            }
        }
        return null;

    }

    /**
     * ��֤���л�ȡ�����㷨������ǩ��
     * 
     * @param certificate
     * @param privateKey
     * @param plainText
     * @return
     */
    public static byte[] sign(X509Certificate certificate,
            PrivateKey privateKey, byte[] plainText) {
        /** ���Ҫ����Կ���ȡǩ���㷨�����ƣ�ֻ�ܽ���ǿ��ת����X509��׼��JDK 6ֻ֧��X.509���͵�֤�� */
        try {
            Signature signature = Signature.getInstance(certificate
                    .getSigAlgName());
            signature.initSign(privateKey);
            signature.update(plainText);
            return signature.sign();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }

    /**
     * ��ǩ����Կ������֤������
     * 
     * @param certificate
     * @param decodedText
     * @param receivedignature
     * @return
     */
    public static boolean verify(X509Certificate certificate,
            byte[] decodedText, final byte[] receivedignature) {
        try {
            Signature signature = Signature.getInstance(certificate
                    .getSigAlgName());
            /** ע�������õ�����֤�飬ʵ�����õ���Ҳ��֤������Ĺ�Կ */
            signature.initVerify(certificate);
            signature.update(decodedText);
            return signature.verify(receivedignature);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return false;
    }

    /**
     * ���ܡ�ע����Կ�ǿ��Ի�ȡ�������õ��㷨�ġ�
     * 
     * @param plainText
     * @param privateKey
     * @return
     */
    public static byte[] encode(byte[] plainText, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(plainText);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;

    }

    /**
     * ���ܣ�ע����Կ�ǿ��Ի�ȡ�����õ��㷨�ġ�
     * 
     * @param encodedText
     * @param publicKey
     * @return
     */
    public static byte[] decode(byte[] encodedText, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(encodedText);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
}

public class CyptoTest{
	public static void main(String[] args){
		//Base64Test.test();
		MessageDiestTest.test();
		//AesTest.test();
		//RsaCyptoTest.test();
		//SignatureTest.test();
		/*
		try {
			CertifacateTest.test();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
	}
}