using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace CandyJun.Aes.Test
{
    [TestClass]
    public class SymmetricAlgorithmExtensionsTest
    {
        [TestMethod]
        public void GenerateKeyTest()
        {
            var plainKey = "1";
            var plain = Encoding.UTF8.GetBytes(plainKey);
            
            var aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateKey(plainKey);
            var csKeyStr = Convert.ToBase64String(aes.Key);
            Assert.AreEqual(csKeyStr, "5syQuHi5SMNekrADx5LEbA==");
        }
    }
}
