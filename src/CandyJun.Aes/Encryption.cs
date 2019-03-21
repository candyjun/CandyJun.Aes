using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace CandyJun.Aes
{
    /// <summary>
    /// 加解密工具库，提供 SHA摘要算法
    /// </summary>
    public class Encryption
    {
        /// <summary>
        /// Sha1摘要
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public static byte[] Sha1Encrypt(byte[] plainText)
        {
            using(var sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(plainText);
            }
        }
    }
}
