using System;
using System.Web;
using System.Web.UI;
using System.Web.Security;
using System.Text;
using System.IO;
using System.Security.Cryptography;

// NB: For dot net your json string will look something like this:
//
// string userDetails = @"{""display_name"":""Richard White"",
// ""avatar_url"":""http:\/\/acme.com\/users\/1234\/avatar.png"",
// ""admin"":""accept"",
// ""expires"":""2009/05/14 03:38:31"",
// ""url"":""http:\/\/acme.com\/users\/1234"",
// ""email"":""rich@acme.com"",
// ""guid"":""1234""}";

namespace Uservoice {
  public class Generator {
    static string create(string userDetails) { 
      string accountKey = "<%= account_key %>";
      string apiKey = "<%= api_key %>";        
      string initVector = "OpenSSL for Ruby"; // DO NOT CHANGE

      byte[] initVectorBytes = Encoding.UTF8.GetBytes(initVector);
      byte[] keyBytesLong;
      using( SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider() ) {
        keyBytesLong = sha.ComputeHash( Encoding.UTF8.GetBytes( apiKey + accountKey ) );
      }
      byte[] keyBytes = new byte[16];
      Array.Copy(keyBytesLong, keyBytes, 16);

      byte[] textBytes = Encoding.UTF8.GetBytes(userDetails);
      for (int i = 0; i < 16; i++) {
        textBytes[i] ^= initVectorBytes[i];
      }

      // Encrypt the string to an array of bytes
      byte[] encrypted = encryptStringToBytes_AES(textBytes, keyBytes, initVectorBytes);
      string encoded = Convert.ToBase64String(encrypted);	
      return HttpUtility.UrlEncode(encoded);
    }

    static byte[] encryptStringToBytes_AES(byte[] textBytes, byte[] Key, byte[] IV) {
      // Declare the stream used to encrypt to an in memory
      // array of bytes and the RijndaelManaged object
      // used to encrypt the data.
      using( MemoryStream msEncrypt = new MemoryStream() )
      using( RijndaelManaged aesAlg = new RijndaelManaged() )
      {
        // Provide the RijndaelManaged object with the specified key and IV.
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.KeySize = 128;
        aesAlg.BlockSize = 128;
        aesAlg.Key = Key;
        aesAlg.IV = IV;
        // Create an encrytor to perform the stream transform.
        ICryptoTransform encryptor = aesAlg.CreateEncryptor();

        // Create the streams used for encryption.
        using( CryptoStream csEncrypt = new CryptoStream( msEncrypt, encryptor, CryptoStreamMode.Write ) ) {
          csEncrypt.Write( textBytes, 0, textBytes.Length );
          csEncrypt.FlushFinalBlock();
        }

        byte[] encrypted = msEncrypt.ToArray(); 
        // Return the encrypted bytes from the memory stream.
        return encrypted;
      }
    }   
  }
}