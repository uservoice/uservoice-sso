package com.uservoice;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.json.JSONObject;

/**
 * Singleton class for creating a UserVoice SSO Token. See {@link #main(String[])} for usage example.
 * Requires commons-codec library {@link http://commons.apache.org/codec/}.
 */
public class TokenGenerator {
  private static final String ACCOUNT_KEY = "<%= account_key %>";
  private static final String API_KEY = "<%= api_key %>";    
  private static final byte[] INIT_VECTOR = "OpenSSL for Ruby".getBytes();  
  private SecretKeySpec secretKeySpec;
  private IvParameterSpec ivSpec;
  private URLCodec urlCodec = new URLCodec("ASCII");
  private Base64 base64 = new Base64();
  private static TokenGenerator INSTANCE = new TokenGenerator();

  public static TokenGenerator getInstance() {
    if (INSTANCE == null) {
      INSTANCE = new TokenGenerator();
    }
    return INSTANCE;
  }

  private TokenGenerator() {
    String salted = API_KEY + ACCOUNT_KEY;
    byte[] hash = DigestUtils.sha(salted);
    byte[] saltedHash = new byte[16];
    System.arraycopy(hash, 0, saltedHash, 0, 16);

    secretKeySpec = new SecretKeySpec(saltedHash, "AES");
    ivSpec = new IvParameterSpec(INIT_VECTOR);
  }

  private void encrypt(InputStream in, OutputStream out) throws Exception {
    try {
      byte[] buf = new byte[1024];
      
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
      
      out = new CipherOutputStream(out, cipher);
      
      int numRead = 0;
      while ((numRead = in.read(buf)) >= 0) {
        out.write(buf, 0, numRead);
      }
      out.close();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    } catch (java.io.IOException e) {
      e.printStackTrace();
    }
  }

  public String create(JSONObject json) throws Exception {
    byte[] data = json.toString().getBytes();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (int i = 0; i < 16; i++) {
      data[i] ^= INIT_VECTOR[i];
    }
    encrypt(new ByteArrayInputStream(data), out);

    String token = new String(urlCodec.encode(base64.encode(out.toByteArray())));
    return token;
  }    

  public static void main(String[] args) {
    try {
      JSONObject jsonObj = new JSONObject();
      
      jsonObj.put("guid", "1234");
      jsonObj.put("expires", "2009-05-18 17:24:28");
      jsonObj.put("display_name", "Richard White");
      jsonObj.put("email", "rich@acme.com");
      jsonObj.put("url", "http://acme.com/users/1234");
      jsonObj.put("avatar_url", "http://acme.com/users/1234/avatar.png");
      
      System.out.println( TokenGenerator.getInstance().create(jsonObj) );
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
