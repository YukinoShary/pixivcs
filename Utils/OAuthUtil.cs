using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace PixivCS.Utils
{
    public class OAuthUtil
    {
        private static readonly char[] padding = { '=' };
        private static string hashSalt = "28c1fdd170a5204386cb1313c7077b34f83e4aaf4aa829ce78c231e05b0bae2c";
        private static readonly string BASE_OAUTH_URL_HOST = "oauth.secure.pixiv.net";
        private static readonly string CLIENT_ID = "MOBrBDS8blbauoSck0ZfDbtuzpyT";
        private static readonly string CLIENT_SECRET = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj";
        private static readonly string REFRESH_CLIENT_ID = "KzEZED7aC0vird8jWyHM38mXjNTY";
        private static readonly string REFRESH_CLIENT_SECRET = "W9JZoJe00qPvJsiyCGT3CCtC6ZUtdpKpzMbNlUGP";
        private HttpClient client;

        public OAuthUtil()
        {
            string time = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss+00:00");
            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "X-Client-Time", time},
                { "X-Client-Hash", (time + hashSalt).GetHashCode().ToString()},
                { "User-Agent", "PixivAndroidApp/5.0.155 (Android 6.0; Pixel C)"},
                { "App-OS", "Android"},
                { "App-OS-Version", "Android 6.0"},
                { "App-Version", "5.0.166"},
                { "Host", BASE_OAUTH_URL_HOST},
                { "Content-Type", "application/x-www-form-urlencoded"}
            };
            /*client = new HttpClient();
            client.BaseAddress = new Uri("https://210.140.131.199");
            client.DefaultRequestHeaders.Add("X-Client-Time", time);
            client.DefaultRequestHeaders.Add("X-Client-Hash", (time + hashSalt).GetHashCode().ToString());
            client.DefaultRequestHeaders.Add("User-Agent", "PixivAndroidApp/5.0.155 (Android 6.0; Pixel C)");
            client.DefaultRequestHeaders.Add("App-OS", "Android");
            client.DefaultRequestHeaders.Add("App-OS-Version", "Android 6.0");
            client.DefaultRequestHeaders.Add("App-Version", "5.0.166");
            client.DefaultRequestHeaders.Add("Host", BASE_OAUTH_URL_HOST);
            client.DefaultRequestHeaders.Add("Content-Type", "application/x-www-form-urlencoded");*/
        }

        public static async Task<string> GenerateWebViewUri()
        {
            string codeVerify = GenerateCodeVerify();
            string codeChallenge = GenerateCodeChallenge(codeVerify);
            string url = "https://app-api.pixiv.net/web/v1/login?code_challenge="+ codeChallenge + "&code_challenge_method=S256&client=pixiv-android";
            return url;
        }
        
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
