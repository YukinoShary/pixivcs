using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net.Http;
using System.Text.Json;

namespace PixivCS.Utils
{
    internal static class OAuthUtil
    {
        private static readonly char[] padding = { '=' };
        
        public static string GenerateCodeVerify()
        {
            byte[] byteArray = new byte[32];
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            provider.GetBytes(byteArray);
            return Convert.ToBase64String(byteArray).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        }

        public static string GenerateCodeChallenge(string code)
        {
            var toByteArray = Encoding.ASCII.GetBytes(code);
            byte[] hashValue = null;
            using (SHA256 mySHA256 = SHA256.Create())
            {
                try
                {
                    hashValue = mySHA256.ComputeHash(toByteArray);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine($"Access Exception: {e.Message}");
                }
                return Convert.ToBase64String(hashValue).TrimEnd(padding).Replace('+', '-').Replace('/', '_');
            }
        }

    }

}
