using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
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
            
            var key = GetKey(plainKey);
            var keyStr = Convert.ToBase64String(key);


            SecureRandom secureRandom = SecureRandom.GetInstance("SHA1PRNG", false);
            secureRandom.SetSeed(plain);

            if(Convert.ToBase64String(SecureRandom.GetNextBytes(secureRandom, 128))==
                Convert.ToBase64String(SecureRandom.GetNextBytes(secureRandom, 128)))
            {

            }

            var aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateKey(plainKey);
            var csKeyStr = Convert.ToBase64String(aes.Key);

            Assert.AreEqual(keyStr, aes.Key);
        }

        private byte[] GetKey(string keySeed)
        {
            SecureRandom secureRandom = SecureRandom.GetInstance("SHA1PRNG", false);
            secureRandom.SetSeed(Encoding.UTF8.GetBytes(keySeed));
            var generator = GeneratorUtilities.GetKeyGenerator("AES");
            generator.Init(new KeyGenerationParameters(secureRandom, 128));
            return generator.GenerateKey();
        }
    }
}
