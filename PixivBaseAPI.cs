using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Security.Cryptography;
using System.Timers;
using PixivCS.Utils;
using PixivCS.Exceptions;

namespace PixivCS
{

    public class RefreshEventArgs : EventArgs
    {
        public string NewAccessToken { get; }
        public string NewRefreshToken { get; }
        public bool IsSuccessful { get; }

        public RefreshEventArgs(string NewAccessToken, string NewRefreshToken, bool IsSuccessful)
        {
            this.NewAccessToken = NewAccessToken;
            this.NewRefreshToken = NewRefreshToken;
            this.IsSuccessful = IsSuccessful;
        }
    }

    public class PixivBaseAPI
    {
        // 参考自下面的链接
        // https://docs.microsoft.com/en-us/aspnet/web-api/overview/advanced/calling-a-web-api-from-a-net-client#create-and-initialize-httpclient
        // https://stackoverflow.com/questions/15705092/do-httpclient-and-httpclienthandler-have-to-be-disposed
        private static HttpClient _client = new HttpClient();

        //需要客户端实现以下ClientLog方法以输出httpclient request log
        public delegate Task ClientOutput(byte[] b);
        public ClientOutput ClientLog { get; set; }

        //允许设置代理
        public static void SetProxy(IWebProxy Proxy)
        {
            HttpClientHandler handler = new HttpClientHandler()
            {
                Proxy = Proxy
            };
            _client = new HttpClient(handler, true);
        }

        //清空代理
        public static void ClearProxy()
        {
            _client = new HttpClient();
        }

        internal string clientID = "MOBrBDS8blbauoSck0ZfDbtuzpyT";
        internal string clientSecret = "lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj";
        internal string hashSecret = "28c1fdd170a5204386cb1313c7077b34f83e4aaf4aa829ce78c231e05b0bae2c";

        public Dictionary<string, string> TargetIPs { get; set; } = new Dictionary<string, string>()
        {
            {"oauth.secure.pixiv.net","210.140.131.199" },
            {"www.pixiv.net","210.140.131.199" },
            {"app-api.pixiv.net","210.140.131.199" }
        };

        public Dictionary<string, string> TargetSubjects { get; set; } = new Dictionary<string, string>()
        {
            {"210.140.131.199","CN=*.pixiv.net, O=pixiv Inc., OU=Development department, L=Shibuya-ku, S=Tokyo, C=JP" },
            {"210.140.92.142","CN=*.pximg.net, OU=Domain Control Validated" }
        };
        public Dictionary<string, string> TargetSNs { get; set; } = new Dictionary<string, string>()
        {
            {"210.140.131.199","346B03F05A00DD2FFAE58853" },
            {"210.140.92.142","2387DB20E84EFCF82492545C" }
        };
        public Dictionary<string, string> TargetTPs { get; set; } = new Dictionary<string, string>()
        {
            {"210.140.131.199","07954CC4735FA33B629899E1DC2591500B090FB5" },
            {"210.140.92.142","F4A431620F42E4D10EB42621C6948E3CD5014FB0" }
        };

        public string AccessToken { get; internal set; }
        public string RefreshToken { get; internal set; }
        public string UserID { get; internal set; }
        public bool ExperimentalConnection { get; set; }
        public string CodeVerify { get; internal set; }
        public string Code { get; internal set; }
        public DateTime AccessTime { get; internal set; }
        public long ExpireTime { get; internal set; }

        public PixivBaseAPI(string AccessToken, string RefreshToken, string UserID,
            ClientOutput ClientLog, bool ExperimentalConnection = false)
        {
            this.AccessToken = AccessToken;
            this.RefreshToken = RefreshToken;
            this.UserID = UserID;
            this.ClientLog = ClientLog;
            this.ExperimentalConnection = ExperimentalConnection;
            ExpireTime = 0;
        }

        public PixivBaseAPI() : this(null, null, null, null) { }

        public PixivBaseAPI(PixivBaseAPI BaseAPI) :
            this(BaseAPI.AccessToken, BaseAPI.RefreshToken, BaseAPI.UserID, BaseAPI.ClientLog, BaseAPI.ExperimentalConnection)
        { }

        //用于生成带参数的url
        private static string GetQueryString(List<(string, string)> query)
        {
            var array = (from i in query
                         select string.Format("{0}={1}", HttpUtility.UrlEncode(i.Item1),
                         HttpUtility.UrlEncode(i.Item2)))
                .ToArray();
            return "?" + string.Join("&", array);
        }

        /// <summary>
        /// 登录验证
        /// </summary>
        /// <exception cref="PixivAuthException">尚未登录</exception>
        public void RequireAuth()
        {
            if (AccessToken == null)
                throw new PixivAuthException("Authentication required!");
        }

        public async Task<HttpResponseMessage> RequestCall(string Method, string Url,
            Dictionary<string, string> Headers = null, List<(string, string)> Query = null,
            HttpContent Body = null)
        {
            string queryUrl = Url + ((Query != null) ? GetQueryString(Query) : "");
            if (ExperimentalConnection && TargetIPs.ContainsKey(new Uri(queryUrl).Host))
            {
                #region 无  底  深  坑
                var targetIP = TargetIPs[new Uri(queryUrl).Host];
                var targetSubject = TargetSubjects[targetIP];
                var targetSN = TargetSNs[targetIP];
                var targetTP = TargetTPs[targetIP];
                using (var connection = await Utilities.CreateConnectionAsync(targetIP, (cert) =>
                    cert.Subject == targetSubject && cert.SerialNumber == targetSN && cert.Thumbprint == targetTP))
                {
                    var httpRequest = await Utilities.ConstructHTTPAsync(Method, queryUrl, Headers, Body);
                    if(ClientLog != null) 
                        await ClientLog(httpRequest);
                    await connection.WriteAsync(httpRequest, 0, httpRequest.Length);
                    using (var memory = new MemoryStream())
                    {
                        await connection.CopyToAsync(memory);
                        memory.Position = 0;
                        var data = memory.ToArray();
                        var index = Utilities.BinaryMatch(data, Encoding.UTF8.GetBytes("\r\n\r\n")) + 4;
                        var headers = Encoding.UTF8.GetString(data, 0, index);
                        memory.Position = index;
                        byte[] result;
                        HttpStatusCode statusCode;
                        Dictionary<string, string> headersDictionary = new Dictionary<string, string>();
                        foreach (var header in headers.Split(new[] { "\r\n" }, StringSplitOptions.None))
                        {
                            if (string.IsNullOrWhiteSpace(header))
                                break;
                            if (!header.Contains(": "))
                            {
                                var status = header.Split(new[] { " " }, StringSplitOptions.None);
                                statusCode = (HttpStatusCode)Convert.ToInt32(status[1]);
                            }
                            else
                            {
                                var pair = header.Split(new[] { ": " }, StringSplitOptions.None);
                                if (pair[0].Equals("Set-Cookie") && headersDictionary.ContainsKey("Set-Cookie"))
                                    headersDictionary["Set-Cookie"] = headersDictionary["Set-Cookie"] + ", " + pair[1];
                                else
                                    headersDictionary.Add(pair[0], pair[1]);
                            }
                        }
                        if (headersDictionary.ContainsKey("Content-Encoding") &&
                            headersDictionary["Content-Encoding"].Contains("gzip"))
                        {
                            using (GZipStream decompressionStream = new GZipStream(memory, CompressionMode.Decompress))
                            using (var decompressedMemory = new MemoryStream())
                            {
                                await decompressionStream.CopyToAsync(decompressedMemory);
                                decompressedMemory.Position = 0;
                                result = decompressedMemory.ToArray();
                            }
                        }
                        else
                        {
                            using (var resultMemory = new MemoryStream())
                            {
                                await memory.CopyToAsync(resultMemory);
                                result = resultMemory.ToArray();
                            }
                        }
                        if (headersDictionary.ContainsKey("Transfer-Encoding") &&
                            headersDictionary["Transfer-Encoding"].Contains("chunked"))
                        {
                            //处理分块传输
                            using (MemoryStream parsedChunckedResult = new MemoryStream())
                            {
                                parsedChunckedResult.Position = 0;
                                int position = 0;
                                bool lengthOrContent = false;
                                int chunkLength = 0;
                                List<byte> lengthList = new List<byte>();
                                while (position < result.Length)
                                {
                                    if (!lengthOrContent)
                                    {
                                        //分块长度信息
                                        if (result[position] == '\r')
                                        {
                                            position += 2;
                                            lengthOrContent = true;
                                            var lengthArray = lengthList.ToArray();
                                            chunkLength = Convert.ToInt32(Encoding.UTF8.GetString(lengthArray), 16);
                                            lengthList.Clear();
                                        }
                                        else
                                        {
                                            lengthList.Add(result[position]);
                                            position++;
                                        }
                                    }
                                    else
                                    {
                                        //末端
                                        if (chunkLength == 0)
                                            break;
                                        //分块内容
                                        await parsedChunckedResult.WriteAsync(result, position, chunkLength);
                                        position += chunkLength + 2;
                                        lengthOrContent = false;
                                    }
                                }
                                result = parsedChunckedResult.ToArray();
                            }
                        }
                        var res = new HttpResponseMessage();
                        res.Content = new ByteArrayContent(result);
                        if (ClientLog != null)
                            await ClientLog(result);
                        foreach (var pair in headersDictionary)
                        {
                            var added = res.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
                            if (!added)
                                res.Content.Headers.Add(pair.Key, pair.Value);
                        }
                        return res;
                    }
                }
                #endregion
            }
            else //传统手段
            {
                var allowMethods = new string[] { "get", "post" };
                if (!allowMethods.Any(m => m.Equals(Method, StringComparison.OrdinalIgnoreCase)))
                    throw new PixivException("Unsupported method");
                
                var request = new HttpRequestMessage(new HttpMethod(Method), queryUrl);
                string bodyStr;
                
                if (!Headers.ContainsKey("Host"))
                    Headers.Add("Host", new Uri(Url).Host);
                if (!Headers.ContainsKey("Cache-Control"))
                    Headers.Add("Cache-Control", "no-cache");
                if (!Headers.ContainsKey("Connection"))
                    Headers.Add("Connection", "Keep-Alive");
                foreach (var pair in Headers)
                    request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
                if (Body != null)
                    request.Content = Body;
                if (Method.Equals("POST"))
                {
                    switch (Body)
                    {
                        case FormUrlEncodedContent form:
                            bodyStr = await form.ReadAsStringAsync();
                            if (!Headers.ContainsKey("Content-Length"))
                                request.Content.Headers.ContentLength = Encoding.UTF8.GetByteCount(bodyStr);
                            break;
                        default:
                            throw new PixivException("Unsupported content type");
                    }
                }
                var result = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                if(ClientLog != null)
                    await ClientLog(await result.Content.ReadAsByteArrayAsync());
                return result;
            }
        }

        public void SetClient(string ClientID, string ClientSecret, string HashSecret)
        {
            clientID = ClientID;
            clientSecret = ClientSecret;
            hashSecret = HashSecret;
        }

        /// <summary>
        /// 获取带有Code Challenge的WebView登录链接
        /// </summary>
        /// <returns></returns>
        public Uri GenerateWebViewUri()
        {
            CodeVerify = OAuthUtil.GenerateCodeVerify();
            string codeChallenge = OAuthUtil.GenerateCodeChallenge(CodeVerify);
            string uri = "https://app-api.pixiv.net/web/v1/login?code_challenge=" + codeChallenge + "&code_challenge_method=S256&client=pixiv-android";
            return new Uri(uri);
        }

        /// <summary>
        /// 用户名和密码登录
        /// </summary>
        /// <remarks>
        /// 通过用户名和密码登录账户<br/>
        /// 此方法将会调用<see cref="AuthAsync(Dictionary{string, string}, Dictionary{string, string})"/>
        /// </remarks>
        /// <exception cref="PixivException">尚不明确的其他错误</exception>
        /// <exception cref="PixivAuthException">用户名密码错误</exception>
        /// <exception cref="HttpRequestException">Http连接失败()</exception>
        [Obsolete("Use WebView&Code2Token method instead")]
        public async Task<Objects.AuthResult> AuthAsync(string Username, string Password)
        {
            string time = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss+00:00");
            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "User-Agent", "PixivAndroidApp/5.0.64 (Android 6.0)" },
                { "X-Client-Time", time },
                { "X-Client-Hash", MD5Hash(time+hashSecret) }
            };
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "get_secure_url", "1" },
                { "client_id", clientID },
                { "client_secret", clientSecret },
                { "grant_type", "password" },
                { "username", Username },
                { "password", Password }
            };
            return await AuthAsync(headers, data);
        }

        /// <summary>
        /// RefreshToken登录
        /// </summary>
        /// <remarks>
        /// 通过RefreshToken登录账户<br/>
        /// 此方法将会调用<see cref="AuthAsync(Dictionary{string, string}, Dictionary{string, string})"/>
        /// </remarks>
        /// <exception cref="PixivException">尚不明确的其他错误</exception>
        /// <exception cref="PixivAuthException">用户名密码错误</exception>
        /// <exception cref="HttpRequestException">Http连接失败()</exception>
        public async Task<Objects.AuthResult> AuthAsync(string RefreshToken)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "User-Agent", "PixivAndroidApp/5.0.64 (Android 6.0)" }
            };
            Dictionary<string, string> data = new Dictionary<string, string>
            {
                { "get_secure_url", "1" },
                { "client_id", clientID },
                { "client_secret", clientSecret },
                { "grant_type", "refresh_token" },
                { "refresh_token", RefreshToken }
            };
            AccessTime = DateTime.UtcNow;
            return await AuthAsync(headers, data);
        }

        /// <summary>
        /// 登录逻辑
        /// </summary>
        /// <remarks>
        /// 负责发送请求以及验证返回内容的方法<br/>
        /// 此方法会修改当前对象的以下属性<br/>
        /// <see cref="AccessToken"/><br/>
        /// <see cref="RefreshToken"/><br/>
        /// <see cref="UserID"/>
        /// </remarks>
        /// <exception cref="PixivException">尚不明确的其他错误</exception>
        /// <exception cref="PixivAuthException">用户名密码错误</exception>
        /// <exception cref="HttpRequestException">Http连接失败()</exception>
        protected virtual async ValueTask<Objects.AuthResult> AuthAsync(Dictionary<string, string> headers, Dictionary<string, string> data)
        {
            const string url = "https://oauth.secure.pixiv.net/auth/token";
            var res = await RequestCall("POST", url, headers, Body: new FormUrlEncodedContent(data)).ConfigureAwait(false);
            var resJSON = await res.GetResult<Objects.AuthResult>().ConfigureAwait(false);
            AccessToken = resJSON.Response.AccessToken;
            UserID = resJSON.Response.User.Id;
            RefreshToken = resJSON.Response.RefreshToken;
            ExpireTime = resJSON.Response.ExpiresIn;
            return resJSON;
        }

        /// <summary>
        ///  使用WebView登录后返回的code完成最后的登录步骤
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        public async Task<Objects.AuthResult> Code2Token(string code)
        {
            AccessTime = DateTime.UtcNow;
            string time = AccessTime.ToString("yyyy-MM-ddTHH:mm:ss+00:00");
            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "X-Client-Time", time},
                { "X-Client-Hash", MD5Hash(time + hashSecret)},
                { "User-Agent", "PixivAndroidApp/5.0.155 (Android 6.0; Pixel C)"},
                { "App-OS", "Android"},
                { "App-OS-Version", "Android 6.0"},
                { "App-Version", "5.0.166"},
                { "Host", "oauth.secure.pixiv.net"},
                { "Content-Type", "application/x-www-form-urlencoded"},
                { "Accept-Language","zh-CN"}
            };
            Dictionary<string, string> body = new Dictionary<string, string>
            {
                { "client_id", clientID },
                { "client_secret", clientSecret },
                { "code", code },
                { "code_verifier", CodeVerify },
                { "redirect_uri", "https://app-api.pixiv.net/web/v1/users/auth/pixiv/callback" },
                { "grant_type", "authorization_code" },
                { "include_policy", "true" }
            };
            return await AuthAsync(headers, body);
        }

        /// <summary>
        /// 计算字符串的MD5值
        /// </summary>
        /// <remarks>
        /// 这个方法将会返回一串16进制的表示MD5的字符串
        /// </remarks>
        /// <param name="Input">将要进行计算的字符串</param>
        /// <returns>MD5字符串</returns>
        protected static string MD5Hash(string Input)
        {
            if (string.IsNullOrEmpty(Input))
                throw new ArgumentNullException(nameof(Input));

            using (var md5 = MD5.Create())
            {
                var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(Input.Trim()));
                StringBuilder builder = new StringBuilder(bytes.Length << 1);
                for (int i = 0; i < bytes.Length; i++)
                    builder.Append(bytes[i].ToString("x2"));
                return builder.ToString();
            }
        }
    }
}