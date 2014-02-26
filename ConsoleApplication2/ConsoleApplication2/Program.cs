using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web;
using System;
using System.Globalization;


public class Crypto
{
    private static byte[] _salt = Encoding.ASCII.GetBytes("olaskeois3jdfluIlulJsss3shent323lskj");

    /// <summary>
    /// Encrypt the given string using AES.  The string can be decrypted using 
    /// DecryptStringAES().  The sharedSecret parameters must match.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
    public static string EncryptStringAES(string plainText, string sharedSecret)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException("plainText");
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException("sharedSecret");

        string outStr = null;                       // Encrypted string to return
        RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

        try
        {
            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

            // Create a RijndaelManaged object
            aesAlg = new RijndaelManaged();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

            // Create a decryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // prepend the IV
                msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                }
                outStr = Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        // Return the encrypted bytes from the memory stream.
        return outStr;
    }

    /// <summary>
    /// Decrypt the given string.  Assumes the string was encrypted using 
    /// EncryptStringAES(), using an identical sharedSecret.
    /// </summary>
    /// <param name="cipherText">The text to decrypt.</param>
    /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
    public static string DecryptStringAES(string cipherText, string sharedSecret)
    {
        if (string.IsNullOrEmpty(cipherText))
            throw new ArgumentNullException("cipherText");
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException("sharedSecret");

        // Declare the RijndaelManaged object
        // used to decrypt the data.
        RijndaelManaged aesAlg = null;

        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;

        try
        {
            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

            // Create the streams used for decryption.                
            byte[] bytes = Convert.FromBase64String(cipherText);
            using (MemoryStream msDecrypt = new MemoryStream(bytes))
            {
                // Create a RijndaelManaged object
                // with the specified key and IV.
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                // Get the initialization vector from the encrypted stream
                aesAlg.IV = ReadByteArray(msDecrypt);
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                }
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        return plaintext;
    }

    private static byte[] ReadByteArray(Stream s)
    {
        byte[] rawLength = new byte[sizeof(int)];
        if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
        {
            throw new SystemException("Stream did not contain properly formatted byte array");
        }

        byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
        if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
        {
            throw new SystemException("Did not read byte array properly");
        }

        return buffer;
    }
}


public class Program
{
    private static Random random = new Random((int)DateTime.Now.Ticks);//thanks to McAden
    public static string RandomString(int size)
    {
        StringBuilder builder = new StringBuilder();
        char ch;
        for (int i = 0; i < size; i++)
        {
            ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
            builder.Append(ch);
        }

        return builder.ToString();
    }


public static void Main()
   {
      // for (int i = 0; i < 20; i++)
      // {
      //     var x = Program.RandomString(10);
      //    System.Console.WriteLine(x);
      //    x = Crypto.EncryptStringAES(x, "temp");
      //    System.Console.WriteLine(x);
      //    x = Crypto.DecryptStringAES(x, "temp");
      //    System.Console.WriteLine(x);
      //}

      string[] x = new string[1000];
      x[0] = "-8a5asdz88=11asdfasdfas3a+sdf62sasfdd332f25829+1223sasdzf657570sd2";
      x[1] = "lsdjfsDKFSJDF323323lk4ssdfjlSJDF32l324klj32SDSF32dwS33DdSds34320893";
      x[2] = "JKALSDLFAKLSFLDFLlskadjfsalkdjflksajfdfl3242320934028349823409240230";
      x[3] = "309284jklsadfAJSDFLXKLJVC324sdf234ASDF324sdfsdlkjew32dswasdfasdfaAAA";

      for (int i = 4; i < 1000; i++)
      {
          x[i] = Program.RandomString(100);
      }

      var falseCount = 0;
      foreach (var item in x)
      {
          //System.Console.WriteLine(item);
          var encrypted = Crypto.EncryptStringAES(item, "EAAAAHBXawUX8ib6pJF0gea3czder4x9KWbLMxDx7AnKFkyG4gUp9D+XzhcemWXnkPLv/3VCCo4oCzFZR6p+mTocJq3tEBz7LNh7sT9uOW+J9XUD");
          //System.Console.WriteLine(encrypted);

          var EncodedURL = HttpUtility.UrlEncode(encrypted);
          var DecodedURL = HttpUtility.UrlDecode(encrypted);
          //System.Console.WriteLine("Encoded URL:"+EncodedURL);
          bool match = DecodedURL.Replace(" ","+") == encrypted;
          if (match)
              falseCount += 1;
          //System.Console.WriteLine(match.ToString());
          //System.Console.WriteLine(DecodedURL);
          //System.Console.WriteLine(encrypted);
          //System.Console.WriteLine("-----------");



          var decrpyted = Crypto.DecryptStringAES(encrypted, "EAAAAHBXawUX8ib6pJF0gea3czder4x9KWbLMxDx7AnKFkyG4gUp9D+XzhcemWXnkPLv/3VCCo4oCzFZR6p+mTocJq3tEBz7LNh7sT9uOW+J9XUD");
          //System.Console.WriteLine(decrpyted);
      }
      System.Console.WriteLine(falseCount);
      System.Console.ReadLine();
   }
}
