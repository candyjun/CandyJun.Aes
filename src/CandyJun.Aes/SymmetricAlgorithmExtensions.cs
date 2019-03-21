using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CandyJun.Aes
{
    /// <summary>
    /// 对称加密算法扩展类
    /// </summary>
    public static class SymmetricAlgorithmExtensions
    {
        /// <summary>
        /// 根据任意长度的字符串key，hash出适合AES加密的密钥（兼容JavaAES加密）
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="key">原始密钥</param>
        /// <param name="finalLength">最终密钥长度</param>
        public static void GenerateKey(this SymmetricAlgorithm algorithm, string key, int finalLength = 16)
        {
            var hashBytes = Encryption.Sha1Encrypt(Encoding.UTF8.GetBytes(key));
            var doubleHashBytes = Encryption.Sha1Encrypt(hashBytes);
            algorithm.Key = doubleHashBytes.Take(finalLength).ToArray();
        }

        /// <summary>
        /// 随机生成字符串key，hash出适合AES加密的密钥（兼容JavaAES加密）
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="sourceLength">原始密钥长度（最大长度32）</param>
        /// <param name="finalLength">最终密钥长度</param>
        /// <returns>原始密钥</returns>
        public static string GenerateKey(this SymmetricAlgorithm algorithm, int sourceLength, int finalLength = 16)
        {
            var key = string.Join("", Guid.NewGuid().ToString("N").Take(sourceLength));
            algorithm.GenerateKey(key, finalLength);
            return key;
        }

        /// <summary>
        /// 根据任意长度的字符串向量，hash出适合AES加密的向量（兼容JavaAES加密）
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="key">原始向量</param>
        /// <param name="finalLength">最终向量长度</param>
        public static void GenerateIV(this SymmetricAlgorithm algorithm, string key, int finalLength = 16)
        {
            var hashBytes = Encryption.Sha1Encrypt(Encoding.UTF8.GetBytes(key));
            var doubleHashBytes = Encryption.Sha1Encrypt(hashBytes);
            algorithm.IV = doubleHashBytes.Take(finalLength).ToArray();
        }

        /// <summary>
        /// 随机生成字符串向量，hash出适合AES加密的向量（兼容JavaAES加密）
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="sourceLength">原始向量长度（最大长度32）</param>
        /// <param name="finalLength">最终向量长度</param>
        /// <returns>原始向量</returns>
        public static string GenerateIV(this SymmetricAlgorithm algorithm, int sourceLength, int finalLength = 16)
        {
            var key = string.Join("", Guid.NewGuid().ToString("N").Take(sourceLength));
            algorithm.GenerateIV(key, finalLength);
            return key;
        }
    }
}
