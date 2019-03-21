using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CandyJun.Aes.Test
{
    [TestClass]
    public class AesExtensionsTest
    {
        System.Security.Cryptography.Aes aes;
        public AesExtensionsTest()
        {
            aes = System.Security.Cryptography.Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.BlockSize = 128;
            aes.GenerateKey(8);
            aes.GenerateIV(8);
        }

        [TestMethod]
        public void Crypto()
        {
            var encData = aes.Encrypt("1");
            var str = aes.Decrypt(encData, mode: CipherMode.ECB);

            Assert.AreEqual("1", str);
        }

        [TestMethod]
        public void CryptoBC()
        {
            var encData = aes.EncryptBC("1", CipherModeBC.ECB, CipherPaddingBC.PKCS7PADDING);
            var str = aes.DecryptBC(encData, "AES/ECB/PKCS7");

            Assert.AreEqual("1", str);
        }

        [TestMethod]
        public void CsharpJava()
        {
            var encData = aes.Encrypt("1", mode: CipherMode.ECB);
            var str = aes.DecryptBC(encData, CipherModeBC.ECB, CipherPaddingBC.PKCS7);

            Assert.AreEqual("1", str);
        }
    }
}
