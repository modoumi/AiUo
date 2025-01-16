using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;
using System.Text;
using AiUo.Configuration;
using AiUo.Logging;
using AiUo.Net;
using AiUo.Randoms;
using AiUo.Security;
using AiUo.Text;

namespace AiUo.AspNet;

/// <summary>
/// 自有客户端访问API时的sign验证器服务
/// sourceKey: 生成密钥时的混入值
/// bothKey: 客户端和服务器根据相同的sourceKey和自定义算法获得的密钥(用于签名)
/// accessKey: 服务器返回给客户端的签名密钥
/// </summary>
public class ClientSignFilterService
{
    public const string DEFAULT_HEADER_NAME = "tfxc-sign";
    public ClientSignFilterElement Element { get; }
    public bool Enabled { get; }
    public string HeaderName { get; } = DEFAULT_HEADER_NAME;
    public string KeySeed { get; } = "hNMmcYykGdCluYqe";
    public int[] KeyIndexes { get; } = { 7, 1, 4, 15, 5, 2, 0, 8, 13, 14, 9, 12, 11, 10, 6, 3 };

    public ClientSignFilterService(string name = null)
    {
        var section = ConfigUtil.GetSection<ClientSignFilterSection>();
        if (section != null)
        {
            name ??= section.DefaultFilterName;
            if (!section.Filters.TryGetValue(name, out var element))
                throw new Exception($"配置AccessSignFilter:Filters不存在name: {name}");

            Element = element;
            Enabled = element.Enabled;
            HeaderName = element.HeaderName ?? DEFAULT_HEADER_NAME;
            KeySeed = element.KeySeed;
            KeyIndexes = element.GetKeyIndexes();
        }
    }

    public string GetBothKey(string sourceBothKey)
        => GetKey(KeySeed, KeyIndexes, sourceBothKey);

    public bool VerifyByBothKey(string sourceBothKey, string data, string sign)
    {
        if (!Enabled)
            return true;
        AiUoUtil.ThrowIfNullOrEmpty($"{GetType().Name}.VerifyByBothKey时,sourceBothKey,data,sign不能为空"
            , sourceBothKey, data, sign);
        var bothKey = GetBothKey(sourceBothKey);
        var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(bothKey));
        var hash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
        return hash == sign;
    }

    public string GetAccessKey(string sourceAccessKey)
        => GetKey(KeySeed, KeyIndexes, sourceAccessKey);
    public string GetAccessKeyEncrypt(string sourceBothKey, string sourceAccessKey)
    {
        var bothKey = GetBothKey(sourceBothKey);
        var accessKey = GetAccessKey(sourceAccessKey);
        var ret = JsAesUtil.Encrypt(accessKey, bothKey);
        return ret;
    }
    /// <summary>
    /// 使用bothKey验证签名，并返回用bothKey加密的accessKey
    /// </summary>
    /// <param name="sourceBothKey"></param>
    /// <param name="data"></param>
    /// <param name="sign"></param>
    /// <param name="sourceAccessKey"></param>
    /// <param name="accessKeyEncrypt"></param>
    /// <returns></returns>
    public bool TryVerifyAndGetAccessKeyEncrypt(string sourceBothKey, string data, string sign, string sourceAccessKey, out string accessKeyEncrypt)
    {
        accessKeyEncrypt = VerifyByBothKey(sourceBothKey, data, sign)
            ? GetAccessKeyEncrypt(sourceBothKey, sourceAccessKey)
            : null;
        return accessKeyEncrypt != null;
    }

    /// <summary>
    /// 使用accessKey验证request.header中的sign
    /// </summary>
    /// <param name="context"></param>
    /// <returns></returns>
    /// <exception cref="CustomException"></exception>
    internal async Task VerifyHeaderSignByAccessKey(HttpContext context)
    {
        if (!Enabled)
            return;
            
        // header => Request.Headers["aiuo-sign"] = sourceAccessKey|sign
        if (!context.Request.Headers.TryGetValue(HeaderName, out var value))
            throw new CustomException(GResponseCodes.G_UNAUTHORIZED, $"header不存在: {HeaderName}");
        var headerValue = Convert.ToString(value);
        var data = headerValue?.Split('|');
        if (data == null || data.Length != 2)
            throw new CustomException(GResponseCodes.G_UNAUTHORIZED, $"header {HeaderName} 值格式错误: {value}");
        var sourceAccessKey = data[0]; //
        var sign = data[1];

        // content
        var content = await AspNetUtil.GetRequestBodyAsync(context);
        content = string.IsNullOrEmpty(content) ? "null" : content;
            
        // hash
        var accessKey = GetAccessKey(sourceAccessKey);
        var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(accessKey));
        var hash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(content)));
        var isValid = hash == sign;
        if (!isValid)
        {
            var msg = $"header {HeaderName} 值无效: {value}";
            LogUtil.GetContextLogger()
                .SetLevel(Microsoft.Extensions.Logging.LogLevel.Warning)
                .AddMessage(msg)
                .AddField("BothKeyVerify.HeaderValue", headerValue)
                .AddField("BothKeyVerify.SourceAccessKey", sourceAccessKey)
                .AddField("BothKeyVerify.AccessKey", accessKey)
                .AddField("BothKeyVerify.Sign", sign)
                .AddField("BothKeyVerify.Hash", hash)
                .AddField("BothKeyVerify.Content", content);

            throw new CustomException(GResponseCodes.G_UNAUTHORIZED, msg);
        }
    }
    private static string GetKey(string seed, int[] indexes, string sourceKey)
    {
        if (seed.Length < indexes.Length)
            throw new Exception("SecurityUtil.GetBothKey()时,约定的constStr长度必须大于等于constIndexes长度");
        var len = indexes.Length;
        var mod = sourceKey.Length % len;
        sourceKey += seed.Substring(0, len - mod);
        var max = sourceKey.Length / len;
        var ret = string.Empty;
        for (int i = 0; i < indexes.Length; i++)
        {
            var idx = i % max * len;
            ret += sourceKey[idx + indexes[i]];
        }
        return ret;
        /* TypeScript代码
            class BothKeyGenerator {
              private _constStr = 'hNMmcYykGdCluYqe';
              private _constIndexes = [7, 1, 4, 15, 5, 2, 0, 8, 13, 14, 9, 12, 11, 10, 6, 3];
              private getBothKey(constStr: string, constIndexes: number[], source: string) {
                var len = constIndexes.length;
                var mod = source.length % len;
                source += constStr.substring(0, len - mod);
                var max = source.length / len;
                var ret = '';
                for (var i = 0; i < constIndexes.length; i++) {
                  var idx = (i % max) * len;
                  ret += source[idx + constIndexes[i]];
                }
                return ret;
              }
              public get(source: string) {
                return this.getBothKey(this._constStr, this._constIndexes, source);
              }
            }
        */
    }

    /// <summary>
    /// 获取新的KeySeed
    /// </summary>
    /// <returns></returns>
    public static string GetNewKeySeed()
        => RandomString.Next(CharsScope.NumbersAndLetters, 16);
    /// <summary>
    /// 获取新的KeyIndexes
    /// </summary>
    /// <returns></returns>
    public static string GetNewKeyIndexes()
        => string.Join(',', RandomUtil.RandomNotRepeat(16, 16));
}