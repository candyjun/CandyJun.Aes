using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using CandyJun.Aes;

namespace CandyJun.Aes.Test
{
    [TestClass]
    public class AesExtensionsTest
    {
        System.Security.Cryptography.Aes aes;
        public AesExtensionsTest()
        {
            aes = System.Security.Cryptography.Aes.Create();
            aes.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.BlockSize = 128;
            aes.GenerateKey(8);
            aes.GenerateIV(8);
        }

        [TestMethod]
        public void Crypto()
        {
            var encData = aes.Encrypt("1");
            var str = aes.Decrypt(encData);

            Assert.AreEqual("1", str);
        }

        [TestMethod]
        public void CryptoBC()
        {
            var encData = aes.EncryptBC("1", "AES/ECB/PKCS7");
            var str = aes.DecryptBC(encData, "AES/ECB/PKCS7");

            Assert.AreEqual("1", str);
        }

        [TestMethod]
        public void CsharpJava()
        {
            var encData = aes.Encrypt("1");
            var str = aes.DecryptBC(encData, "AES/ECB/PKCS7Padding");

            Assert.AreEqual("1", str);
        }
    }
}
