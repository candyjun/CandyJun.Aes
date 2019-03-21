using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;
using System.Text;

namespace CandyJun.Aes
{
    /// <summary>
    /// AES加解密扩展类
    /// </summary>
    public static class AesExtensions
    {
        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待加密的字符串（UTF8编码）</param>
        /// <param name="key">加密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">加密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>base64编码格式加密字符串</returns>
        public static string Encrypt(this System.Security.Cryptography.Aes aes,
            string str, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            return aes.Encrypt(str, Encoding.UTF8, key, mode, padding);
        }

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待加密的字符串</param>
        /// <param name="encoding">待加密的字符串编码格式</param>
        /// <param name="key">加密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">加密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>base64编码格式加密字符串</returns>
        public static string Encrypt(this System.Security.Cryptography.Aes aes,
            string str, Encoding encoding, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            var data = encoding.GetBytes(str);
            var encData = aes.Encrypt(data, key, mode, padding);
            return Convert.ToBase64String(encData);
        }

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="data">待加密的数据</param>
        /// <param name="key">加密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">加密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>加密后数据</returns>
        public static byte[] Encrypt(this System.Security.Cryptography.Aes aes,
            byte[] data, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            return aes.Crypto(true, data, key, mode, padding);
        }

        /// <summary>
        /// AES加密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待加密的字符串（UTF8编码）</param>
        /// <param name="algorithm">加密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>base64编码格式加密字符串</returns>
        public static string EncryptBC(this System.Security.Cryptography.Aes aes,
            string str, string algorithm, byte[] key = null, byte[] iv = null)
        {
            return aes.EncryptBC(str, Encoding.UTF8, algorithm, key, iv);
        }

        /// <summary>
        /// AES加密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待加密的字符串</param>
        /// <param name="encoding">待加密的字符串编码格式</param>
        /// <param name="algorithm">加密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>base64编码格式加密字符串</returns>
        public static string EncryptBC(this System.Security.Cryptography.Aes aes,
            string str, Encoding encoding, string algorithm, byte[] key = null, byte[] iv = null)
        {
            var data = encoding.GetBytes(str);
            var result = aes.EncryptBC(data, algorithm, key, iv);
            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// AES加密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="data">待加密的数据</param>
        /// <param name="algorithm">加密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>加密数据</returns>
        public static byte[] EncryptBC(this System.Security.Cryptography.Aes aes,
            byte[] data, string algorithm, byte[] key = null, byte[] iv = null)
        {
            return aes.CryptoBC(true, data, algorithm, key, iv);
        }

        /// <summary>
        /// AES加密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待加密的字符串（UTF8编码）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>base64编码格式加密字符串</returns>
        public static string EncryptBC(this System.Security.Cryptography.Aes aes,
            string str, CipherModeBC mode, CipherPaddingBC padding, byte[] key = null, byte[] iv = null)
        {
            return aes.EncryptBC(str, Encoding.UTF8, mode, padding, key, iv);
        }

        /// <summary>
        /// AES加密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待加密的字符串</param>
        /// <param name="encoding">待加密的字符串编码格式</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>base64编码格式加密字符串</returns>
        public static string EncryptBC(this System.Security.Cryptography.Aes aes,
            string str, Encoding encoding, CipherModeBC mode, CipherPaddingBC padding, byte[] key = null, byte[] iv = null)
        {
            var data = encoding.GetBytes(str);
            var result = aes.EncryptBC(data, mode, padding, key, iv);
            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// AES加密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="data">待加密的数据</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>加密数据</returns>
        public static byte[] EncryptBC(this System.Security.Cryptography.Aes aes,
            byte[] data, CipherModeBC mode, CipherPaddingBC padding, byte[] key = null, byte[] iv = null)
        {
            return aes.CryptoBC(true, data, mode, padding, key, iv);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待解密的字符串（base64编码格式）</param>
        /// <param name="key">解密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">解密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>UTF8编码格式解密字符串</returns>
        public static string Decrypt(this System.Security.Cryptography.Aes aes,
            string str, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            return aes.Decrypt(str, Encoding.UTF8, key, mode, padding);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待解密的字符串（base64编码格式）</param>
        /// <param name="encoding">解密后字符串编码格式</param>
        /// <param name="key">解密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">解密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>解密字符串</returns>
        public static string Decrypt(this System.Security.Cryptography.Aes aes,
            string str, Encoding encoding, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            var data = Convert.FromBase64String(str);
            var encData = aes.Decrypt(data, key, mode, padding);
            return encoding.GetString(encData);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="data">待解密的数据</param>
        /// <param name="key">解密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">解密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>解密后数据</returns>
        public static byte[] Decrypt(this System.Security.Cryptography.Aes aes,
            byte[] data, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            return aes.Crypto(false, data, key, mode, padding);
        }

        /// <summary>
        /// AES解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待解密的字符串（base64编码格式）</param>
        /// <param name="algorithm">解密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>UTF8编码解密字符串</returns>
        public static string DecryptBC(this System.Security.Cryptography.Aes aes,
            string str, string algorithm, byte[] key = null, byte[] iv = null)
        {
            return aes.DecryptBC(str, Encoding.UTF8, algorithm, key, iv);
        }

        /// <summary>
        /// AES解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待解密的字符串（base64编码格式）</param>
        /// <param name="encoding">待解密的字符串编码格式</param>
        /// <param name="algorithm">解密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>解密字符串</returns>
        public static string DecryptBC(this System.Security.Cryptography.Aes aes,
            string str, Encoding encoding, string algorithm, byte[] key = null, byte[] iv = null)
        {
            var data = Convert.FromBase64String(str);
            var result = aes.DecryptBC(data, algorithm, key, iv);
            return encoding.GetString(result);
        }

        /// <summary>
        /// AES解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="data">待解密的数据</param>
        /// <param name="algorithm">解密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>解密后数据</returns>
        public static byte[] DecryptBC(this System.Security.Cryptography.Aes aes,
            byte[] data, string algorithm, byte[] key = null, byte[] iv = null)
        {
            return aes.CryptoBC(false, data, algorithm, key, iv);
        }

        /// <summary>
        /// AES解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待解密的字符串（base64编码格式）</param>
        /// <param name="mode">解密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>UTF8编码解密字符串</returns>
        public static string DecryptBC(this System.Security.Cryptography.Aes aes,
            string str, CipherModeBC mode, CipherPaddingBC padding, byte[] key = null, byte[] iv = null)
        {
            return aes.DecryptBC(str, Encoding.UTF8, mode, padding, key, iv);
        }

        /// <summary>
        /// AES解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="str">待解密的字符串（base64编码格式）</param>
        /// <param name="encoding">待解密的字符串编码格式</param>
        /// <param name="mode">解密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>解密字符串</returns>
        public static string DecryptBC(this System.Security.Cryptography.Aes aes,
            string str, Encoding encoding, CipherModeBC mode, CipherPaddingBC padding, 
            byte[] key = null, byte[] iv = null)
        {
            var data = Convert.FromBase64String(str);
            var result = aes.DecryptBC(data, mode, padding, key, iv);
            return encoding.GetString(result);
        }

        /// <summary>
        /// AES解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="data">待解密的数据</param>
        /// <param name="mode">解密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>解密后数据</returns>
        public static byte[] DecryptBC(this System.Security.Cryptography.Aes aes,
            byte[] data, CipherModeBC mode, CipherPaddingBC padding, byte[] key = null, byte[] iv = null)
        {
            return aes.CryptoBC(false, data, mode, padding, key, iv);
        }

        /// <summary>
        /// AES加解密
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="forEncryption">是否加密（false为解密）</param>
        /// <param name="data">待加解密的数据</param>
        /// <param name="key">加解密密钥，为空则使用实体属性Key</param>
        /// <param name="mode">加解密模式，为空则使用实体属性Mode</param>
        /// <param name="padding">填充算法，为空则使用实体属性Padding</param>
        /// <returns>加解密后数据</returns>
        public static byte[] Crypto(this System.Security.Cryptography.Aes aes,
            bool forEncryption, byte[] data, byte[] key = null, CipherMode? mode = null, PaddingMode? padding = null)
        {
            aes.Key = key ?? aes.Key;
            aes.Mode = mode ?? aes.Mode;
            aes.Padding = padding ?? aes.Padding;
            var cryptor = forEncryption ? aes.CreateEncryptor() : aes.CreateDecryptor();
            return cryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <summary>
        /// AES加解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="forEncryption">是否加密（false为解密）</param>
        /// <param name="data">待加解密的数据</param>
        /// <param name="mode">加解密模式</param>
        /// <param name="padding">填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>加解密后数据</returns>
        public static byte[] CryptoBC(this System.Security.Cryptography.Aes aes,
            bool forEncryption, byte[] data, CipherModeBC mode, CipherPaddingBC padding, byte[] key, byte[] iv)
        {
            return aes.CryptoBC(forEncryption, data, $"AES/{mode}/{padding}", key, iv);
        }

        /// <summary>
        /// AES加解密（BouncyCastle模式）
        /// </summary>
        /// <param name="aes"></param>
        /// <param name="forEncryption">是否加密（false为解密）</param>
        /// <param name="data">待加解密的数据</param>
        /// <param name="algorithm">加解密模式、填充算法</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">向量</param>
        /// <returns>加解密后数据</returns>
        public static byte[] CryptoBC(this System.Security.Cryptography.Aes aes,
            bool forEncryption, byte[] data, string algorithm, byte[] key, byte[] iv)
        {
            aes.Key = key ?? aes.Key;
            aes.IV = iv ?? aes.IV;
            var cipher = CipherUtilities.GetCipher(algorithm);
            try
            {
                cipher.Init(forEncryption, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", aes.Key), aes.IV));
            }
            catch (ArgumentException)
            {
                cipher.Init(forEncryption, ParameterUtilities.CreateKeyParameter("AES", aes.Key));
            }
            return cipher.DoFinal(data);
        }
    }
}
