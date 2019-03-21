using System;
using System.Security.Cryptography;

namespace CandyJun.Aes.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            var aes = System.Security.Cryptography.Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.BlockSize = 128;
            aes.GenerateKey(8);
            aes.GenerateIV(8);

            var source = "test";
            Console.WriteLine($"Source:{source}");
            var encCsharp = aes.Encrypt(source);
            Console.WriteLine($"Encrypt:{encCsharp}");
            var strCsharp = aes.Decrypt(encCsharp, mode: CipherMode.ECB);
            Console.WriteLine($"Decrypt:{strCsharp}");

            var encBC = aes.EncryptBC(source, "AES/ECB/PKCS7");
            Console.WriteLine($"EncryptBC:{encCsharp}");
            Console.WriteLine($"Are equal:{encCsharp == encBC}");
            var strBC = aes.DecryptBC(encCsharp, CipherModeBC.ECB, CipherPaddingBC.PKCS7);
            Console.WriteLine($"DecryptBC:{strBC}");

            Console.WriteLine($"Are equal:{strBC == source}");

            Console.ReadKey();
        }
    }
}
