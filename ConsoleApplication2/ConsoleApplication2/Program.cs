using System;
using System.Text;
using System.Web;

public class Program
{
    private static Random random = new Random((int)DateTime.Now.Ticks);

    /// <summary>
    /// Makes random strings for testing
    /// </summary>
    /// <param name="size">size of string</param>
    /// <returns>the random string</returns>
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

    /// <summary>
    /// This is the test section for Crypto
    /// </summary>
    public static void Main()
    {
        string[] strArray = new string[100];
        strArray[0] = "-8a5asdz88=11asdfasdfas3a+sdf62sasfdd332f25829+1223sasdzf657570sd2";
        strArray[1] = "lsdjfsDKFSJDF323323lk4ssdfjlSJDF32l324klj32SDSF32dwS33DdSds34320893";
        strArray[2] = "JKALSDLFAKLSFLDFLlskadjfsalkdjflksajfdfl3242320934028349823409240230";
        strArray[3] = "309284jklsadfAJSDFLXKLJVC324sdf234ASDF324sdfsdlkjew32dswasdfasdfaAAA";

        for (int i = 4; i < 100; i++)
        {
            strArray[i] = Program.RandomString(100);
        }

        var falseCount = 0;
        foreach (var item in strArray)
        {
            //System.Console.WriteLine(item);
            var encrypted = Crypto.EncryptStringAES(item, "EAAAAHBXawUX8ib6pJF0gea3czder4x9KWbLMxDx7AnKFkyG4gUp9D+XzhcemWXnkPLv/3VCCo4oCzFZR6p+mTocJq3tEBz7LNh7sT9uOW+J9XUD");
            //System.Console.WriteLine(encrypted);

            var EncodedURL = HttpUtility.UrlEncode(encrypted);
            var DecodedURL = HttpUtility.UrlDecode(encrypted);
            //System.Console.WriteLine("Encoded URL:"+EncodedURL);
            bool match = DecodedURL.Replace(" ", "+") == encrypted;
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

    /// <summary>
    /// This is a test section for PasswordHash
    /// </summary>
    public static void Main1()
    {
        string[] strArrayHash = new string[100];

        for (int i = 0; i < 100; i++)
        {
            strArrayHash[i] = Program.RandomString(10);
        }

        foreach (var item in strArrayHash)
        {
            var hashVal = PasswordHash.PasswordHash.CreateHash(item);
            var hashVa2 = PasswordHash.PasswordHash.CreateHash(item);
            var hashVa3 = PasswordHash.PasswordHash.CreateHash(item);
            var CheckHash1 = PasswordHash.PasswordHash.ValidatePassword(item, hashVal);
            var CheckHash2 = PasswordHash.PasswordHash.ValidatePassword(item, hashVa2);
            var CheckHash3 = PasswordHash.PasswordHash.ValidatePassword(item, hashVa3);
            Console.WriteLine("value:" + item);
            Console.WriteLine("hash1:" + hashVal);
            Console.WriteLine("hash2:" + hashVa2);
            Console.WriteLine("hash3:" + hashVa3);
            Console.WriteLine(CheckHash1.ToString() + CheckHash2 + CheckHash3);
        }

        System.Console.ReadLine();
    }
}