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
		System.out.println("HmacSHA256：" + MAC(PLAIN_TEXT.getBytes(),MAC_ALGORITHM_256));
		System.out.println("HmacSHA512：" + MAC(PLAIN_TEXT.getBytes(),MAC_ALGORITHM_512));
	}
	
	/**
	 *  ascii 转换
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
     * 1.消息摘要算法，MD家族，有MD2 MD4 MD5，其中MD4 JDK不支持
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
     * 2.SHA Security Hash Algorithm 安全散列算法，固定长度摘要信息 SHA-1 SHA-2( SHA-224
     * SHA-256 SHA-384 SHA-512) 使用的依然是MessageDigest类，JDK不支持224
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
     * 3.MAC(Message Authentication Code) 消息认证码算法，是含有密钥散列函数算法。
     * 兼容了MD和SHA的特性。
     * 加密过程三步走，与后面要介绍的对称加密和非对称加密是相似的
     * 1) 传入算法，实例化一个加密器
     * 2) 传入密钥，初始化加密器
     * 3) 调用doFinal方法进行加密
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
     * MAC生成随机密钥 两步走 1.创建一个KeyGenerator 2.调用KeyGenerator.generateKey方法
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
     * 还原密钥
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
	     * 注意key和加密用到的字符串是不一样的 加密还要指定填充的加密模式和填充模式 AES密钥可以是128或者256，加密模式包括ECB, CBC等
	     * ECB模式是分组的模式，CBC是分块加密后，每块与前一块的加密结果异或后再加密 第一块加密的明文是与IV变量进行异或
	     */
	    private static final String KEY_ALGORITHM = "AES";
	    private static final String ECB_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
	    private static final String CBC_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	    private static final String PLAIN_TEXT = "MANUTD is the greatest club in the world";

	    /**
	     * IV(Initialization Value)是一个初始值，对于CBC模式来说，它必须是随机选取并且需要保密的
	     * 而且它的长度和密码分组相同(比如：对于AES 128为128位，即长度为16的byte类型数组)
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
	     * 使用ECB模式进行加密。 加密过程三步走： 1. 传入算法，实例化一个加解密器 2. 传入加密模式和密钥，初始化一个加密器 3.
	     * 调用doFinal方法加密
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
	     * 使用ECB解密，三步走，不说了
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
	     * CBC加密，三步走，只是在初始化时加了一个初始变量
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
	     * CBC 解密
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
	     * 1.创建一个KeyGenerator 2.调用KeyGenerator.generateKey方法
	     * 由于某些原因，这里只能是128，如果设置为256会报异常，原因在下面文字说明
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
	     * 还原密钥
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
    /** 貌似默认是RSA/NONE/PKCS1Padding，未验证 */
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";

    /** RSA密钥长度必须是64的倍数，在512~65536之间。默认是1024 */
    public static final int KEY_SIZE = 2048;

    public static final String PLAIN_TEXT = "MANUTD is the greatest club in the world";

    public static void test() {
        Map<String, byte[]> keyMap = generateKeyBytes();

        // 加密
        PublicKey publicKey = restorePublicKey(keyMap.get(PUBLIC_KEY));
   
        byte[] encodedText = RSAEncode(publicKey, PLAIN_TEXT.getBytes());
        System.out.println("RSA encoded: " + Base64.getEncoder().encodeToString(encodedText));

        // 解密
        PrivateKey privateKey = restorePrivateKey(keyMap.get(PRIVATE_KEY));
        System.out.println("RSA decoded: "
                + RSADecode(privateKey, encodedText));
    }

    /**
     * 生成密钥对。注意这里是生成密钥对KeyPair，再由密钥对获取公私钥
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
     * 还原公钥，X509EncodedKeySpec 用于构建公钥的规范
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
     * 还原私钥，PKCS8EncodedKeySpec 用于构建私钥的规范
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
     * 加密，三步走。
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
     * 解密，三步走。
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
 * RSA数字签名，借用RsaCyptoTest中的算法，不再重复
 * 数字签名遵循“私钥签名，公钥验签”原则，因为私钥是个人身份认证
 * @author Kinsley
 *
 */
class SignatureTest {
    
    /** 数字签名算法。JDK只提供了MD2withRSA, MD5withRSA, SHA1withRSA，其他的算法需要第三方包才能支持 */
    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    
    public static final String PLAIN_TEXT = "MANUTD is the greatest club in the world";
    public static void test()
    {
        //建立两套公私钥对
        Map<String, byte[]> keyMapA = RsaCyptoTest.generateKeyBytes();
        PublicKey publicKeyA = RsaCyptoTest.restorePublicKey(keyMapA.get(RsaCyptoTest.PUBLIC_KEY));
        PrivateKey privateKeyA = RsaCyptoTest.restorePrivateKey(keyMapA.get(RsaCyptoTest.PRIVATE_KEY));
        
        Map<String, byte[]> keyMapB = RsaCyptoTest.generateKeyBytes();
        PublicKey publicKeyB =RsaCyptoTest.restorePublicKey(keyMapB.get(RsaCyptoTest.PUBLIC_KEY));
        PrivateKey privateKeyB =RsaCyptoTest.restorePrivateKey(keyMapB.get(RsaCyptoTest.PRIVATE_KEY));
        
        /** 假设现在A签名后向B发送消息
         * A用B的公钥进行加密
         * 用自己A的私钥进行签名
         */
        byte[] encodedText = RsaCyptoTest.RSAEncode(publicKeyB, PLAIN_TEXT.getBytes());
        byte[] signature = sign(privateKeyA, PLAIN_TEXT.getBytes());
        
        /**
         * 现在B收到了A的消息，进行两步操作
         * 用B的私钥解密得到明文
         * 将明文和A的公钥进行验签操作
         */
        
        byte[] decodedText = RsaCyptoTest.RSADecode(privateKeyB, encodedText).getBytes();
        System.out.println("Decoded Text: " + new String(decodedText));
        
        System.out.println("Signature is " + verify(publicKeyA, signature, decodedText));
    }
    
    /**
     * 签名，三步走
     * 1. 实例化，传入算法
     * 2. 初始化，传入私钥
     * 3. 签名
     * @param key
     * @param plainText
     * @return
     */
    public static byte[] sign(PrivateKey privateKey, byte[] plainText)
    {
        try {
            //实例化
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            
            //初始化，传入私钥
            signature.initSign(privateKey);
            
            //更新
            signature.update(plainText);
            
            //签名
            return signature.sign();
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return null;
    }
    
    /**
     * 验签，三步走
     * 1. 实例化，传入算法
     * 2. 初始化，传入公钥
     * 3. 验签
     * @param publicKey
     * @param signatureVerify
     * @param plainText
     * @return
     */
    public static boolean verify(PublicKey publicKey, byte[] signatureVerify, byte[] plainText )
    {
        try {
            //实例化
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            
            //初始化
            signature.initVerify(publicKey);
            
            //更新
            signature.update(plainText);
            
            //验签
            return signature.verify(signatureVerify);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return false;
    }
}

/** 1.构建自签名证书
 * 	keytool -genkeypair -keyalg RSA -keysize 2048 -sigalg SHA1withRSA -validity 3600 -alias myCertificate -keystore myKeystore.keystore
 * 2.导出证书
 * 	keytool -exportcert -alias myCertificate -keystore myKeystore.keystore -file myCer.cer -rfc
 * 3.构建签发申请
 * keytool -certreq -alias myCertificate -keystore myKeystore.keystore -file myCsr.csr -v
 * 4.导入证书
 * keytool -importcert -trustcacerts -alias myCertificate -file myCer.cer -keystore myKeystore.keystore
 * 5.查看证书
 * keytool -list -alias myCertificate -keystore myKeystore.keystore
 */
class CertifacateTest {
    private static final String STORE_PASS = "123456";
    private static final String ALIAS = "myCertificate";
    private static final String KEYSTORE_PATH = "F:\\eclipse\\workspace\\CertTestPath\\myKeystore.keystore";
    private static final String CERT_PATH = "F:\\eclipse\\workspace\\CertTestPath\\myCer.cer";
    private static final String PLAIN_TEXT = "MANUTD is the most greatest club in the world.";
    /** JDK6只支持X.509标准的证书 */
    private static final String CERT_TYPE = "X.509";

    public static void test() throws IOException {
        /**
         * 假设现在有这样一个场景 。A机器上的数据，需要加密导出，然后将导出文件放到B机器上导入。 在这个场景中，A相当于服务器，B相当于客户端
         */

        /** A */
        KeyStore keyStore = getKeyStore(STORE_PASS, KEYSTORE_PATH);
        PrivateKey privateKey = getPrivateKey(keyStore, ALIAS, STORE_PASS);
        X509Certificate certificate = getCertificateByKeystore(keyStore, ALIAS);

        /** 加密和签名 */
        byte[] encodedText = encode(PLAIN_TEXT.getBytes(), privateKey);
        byte[] signature = sign(certificate, privateKey, PLAIN_TEXT.getBytes());

        /** 现在B收到了A的密文和签名，以及A的可信任证书 */
        X509Certificate receivedCertificate = getCertificateByCertPath(
                CERT_PATH, CERT_TYPE);
        PublicKey publicKey = getPublicKey(receivedCertificate);
        byte[] decodedText = decode(encodedText, publicKey);
        System.out.println("Decoded Text : " + new String(decodedText));
        System.out.println("Signature is : "
                + verify(receivedCertificate, decodedText, signature));
    }

    /**
     * 加载密钥库，与Properties文件的加载类似，都是使用load方法
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
     * 获取私钥
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
     * 获取公钥
     * 
     * @param certificate
     * @return
     */
    public static PublicKey getPublicKey(Certificate certificate) {
        return certificate.getPublicKey();
    }

    /**
     * 通过密钥库获取数字证书，不需要密码，因为获取到Keystore实例
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
     * 通过证书路径生成证书，与加载密钥库差不多，都要用到流。
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
            // 实例化证书工厂
            CertificateFactory factory = CertificateFactory
                    .getInstance(certType);
            // 取得证书文件流
            inputStream = new FileInputStream(path);
            // 生成证书
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
     * 从证书中获取加密算法，进行签名
     * 
     * @param certificate
     * @param privateKey
     * @param plainText
     * @return
     */
    public static byte[] sign(X509Certificate certificate,
            PrivateKey privateKey, byte[] plainText) {
        /** 如果要从密钥库获取签名算法的名称，只能将其强制转换成X509标准，JDK 6只支持X.509类型的证书 */
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
     * 验签，公钥包含在证书里面
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
            /** 注意这里用到的是证书，实际上用到的也是证书里面的公钥 */
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
     * 加密。注意密钥是可以获取到它适用的算法的。
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
     * 解密，注意密钥是可以获取它适用的算法的。
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