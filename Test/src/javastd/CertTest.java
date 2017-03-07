package javastd;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;

import javax.naming.Context;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/** 
 * Created With IntelliJ IDEA. 
 * 
 * @author : lee 
 * @group : sic-ca 
 * @Date : 2014/12/30 
 * @Comments : 配置接口 
 * @Version : 1.0.0 
 */  
@SuppressWarnings("deprecation")
interface CAConfig {  
  
    /** 
     * C 
     */  
    String CA_C = "CN";  
    /** 
     * ST 
     */  
    String CA_ST = "BJ";  
    /** 
     * L 
     */  
    String CA_L = "BJ";  
    /** 
     */                                                                                                                                                                                                                                    
    String CA_O = "SICCA";  
      
    /** 
     * CA_ROOT_ISSUER 
     */  
    String CA_ROOT_ISSUER="C=CN,ST=BJ,L=BJ,O=SICCA,OU=SC,CN=SICCA";  
    /** 
     * CA_DEFAULT_SUBJECT 
     */  
    String CA_DEFAULT_SUBJECT="C=CN,ST=BJ,L=BJ,O=SICCA,OU=SC,CN=";  
      
    String CA_SHA="SHA256WithRSAEncryption";  
    

}

/** 
 * Created With IntelliJ IDEA. 
 * 
 * @author : lee 
 * @group : sic-ca 
 * @Date : 2014/12/30 
 * @Comments : 证书类 
 * @Version : 1.0.0 
 */  
@SuppressWarnings("all")  
class BaseCert {  
    /** 
     * BouncyCastleProvider 
     */  
    static {  
        Security.addProvider(new BouncyCastleProvider());  
    }  
    /** 
     *  
     */  
    protected static KeyPairGenerator kpg = null;  
  
    /** 
 *  
 */  
    public BaseCert() {  
        try {  
            // 采用 RSA 非对称算法加密  
            kpg = KeyPairGenerator.getInstance("RSA");  
            // 初始化为 1023 位  
            kpg.initialize(1024);  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
  
    }  

    /** 
     * 生成 X509 证书 
     * @param user 
     * @return 
     */  
    public X509CertificateObject generateCert(String user) {    
    	try {
        // Create a new pair of RSA keys using BouncyCastle classes
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3),
                new SecureRandom(), 1024, 80));
        AsymmetricCipherKeyPair keypair = gen.generateKeyPair();
        RSAKeyParameters publicKey = (RSAKeyParameters) keypair.getPublic();
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keypair
                .getPrivate();

        // We also need our pair of keys in another format, so we'll convert
        // them using java.security classes
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(publicKey.getModulus(), publicKey
                        .getExponent()));
        PrivateKey privKey = KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateCrtKeySpec(publicKey.getModulus(), publicKey
                        .getExponent(), privateKey.getExponent(),
                        privateKey.getP(), privateKey.getQ(), privateKey
                                .getDP(), privateKey.getDQ(), privateKey
                                .getQInv()));

        // CName or other certificate details do not really matter here
        //X509Name x509Name = new X509Name("CN=" + CNAME);

        // We have to sign our public key now. As we do not need or have
        // some kind of CA infrastructure, we are using our new keys
        // to sign themselves

        // Set certificate meta information
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(System
                .currentTimeMillis())));
        certGen.setIssuer(new X500Name(CAConfig.CA_ROOT_ISSUER));
        certGen.setIssuerUniqueID(new DERBitString(CAConfig.CA_ROOT_ISSUER.getBytes()));
        certGen.setIssuer(new X500Name(CAConfig.CA_DEFAULT_SUBJECT+user));
        certGen.setSubjectUniqueID(new DERBitString((CAConfig.CA_DEFAULT_SUBJECT+user).getBytes()));
        ASN1ObjectIdentifier sigOID = PKCSObjectIdentifiers.sha1WithRSAEncryption;
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(sigOID);
        certGen.setSignature(sigAlgId);
        ByteArrayInputStream bai = new ByteArrayInputStream(
                pubKey.getEncoded());
        ASN1InputStream ais = new ASN1InputStream(bai);
        certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo(
        		sigAlgId,pubKey.getEncoded()));
        bai.close();
        ais.close();

        // We want our keys to live long
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, 365 * 30);

        certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
        certGen.setEndDate(new Time(expiry.getTime()));
        
        Extensions aExtensions=null;
		certGen.setExtensions(aExtensions);
		
        TBSCertificate tbsCert = certGen.generateTBSCertificate();

        // The signing: We first build a hash of our certificate, than sign
        // it with our private key
        SHA1Digest digester = new SHA1Digest();
        AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSAEngine());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(tbsCert);
        byte[] signature;
        byte[] certBlock = bOut.toByteArray();
        // first create digest
        digester.update(certBlock, 0, certBlock.length);
        byte[] hash = new byte[digester.getDigestSize()];
        digester.doFinal(hash, 0);
        // and sign that
        rsa.init(true, privateKey);
        DigestInfo dInfo = new DigestInfo(new AlgorithmIdentifier(
                X509ObjectIdentifiers.id_SHA1, null), hash);
        byte[] digest = dInfo.getEncoded(ASN1Encoding.DER);
        signature = rsa.processBlock(digest, 0, digest.length);
        dOut.close();
        
        // We build a certificate chain containing only one certificate
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(sigAlgId);
        v.add(new DERBitString(signature));
        X509CertificateObject clientCert = new X509CertificateObject(
        		Certificate.getInstance(ASN1Sequence.getInstance(v)));
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = clientCert;

        // We add our certificate to a new keystore
        KeyStore keyStore = KeyStore.getInstance("BKS");
        keyStore.load(null);
        keyStore.setKeyEntry("MyKeyStore", (Key) privKey,
                "123456".toCharArray(), chain);
        
        // We write this keystore to a file
        OutputStream out = new FileOutputStream("F:/eclipse/workspace/CertTestPath/dong1.cer");
        keyStore.store(out, "123456".toCharArray());
        out.close();
        return clientCert;
    } catch (Exception e) {
        // Do your exception handling here
        // There is a lot which might go wrong
        e.printStackTrace();
    }
    return null;
    }  
}

/** 
 * Created With IntelliJ IDEA. 
 * 
 * @author : lee 
 * @group : sic-ca 
 * @Date : 2014/12/30 
 * @Comments : 测试证书类 
 * @Version : 1.0.0 
 */  
public class CertTest {  
    private static String certPath = "F:/eclipse/workspace/CertTestPath/dong.cer";  
    public static void main(String[] args) {  
        BaseCert baseCert = new BaseCert();  
        X509CertificateObject cert = baseCert.generateCert("Lee");  
        System.out.println(cert.toString());  
  
        // 导出为 cer 证书  
        try {  
            FileOutputStream fos = new FileOutputStream(certPath);  
            fos.write(cert.getEncoded());  
            fos.close();  
        } catch (FileNotFoundException e) {  
            e.printStackTrace();  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
    }  
}