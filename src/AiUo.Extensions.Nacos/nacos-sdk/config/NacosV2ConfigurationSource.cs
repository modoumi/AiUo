﻿namespace Nacos.Microsoft.Extensions.Configuration;

using global::Microsoft.Extensions.Configuration;
using Nacos;
using Nacos.Config.Parser;
using Nacos.Utils;
using System;
using System.Collections.Generic;

public class NacosV2ConfigurationSource : NacosSdkOptions, IConfigurationSource
{
    /// <summary>
    /// The INacosConfigService.
    /// </summary>
    internal INacosConfigService Client;

    /// <summary>
    /// The configuration listeners
    /// </summary>
    public List<ConfigListener> Listeners { get; set; }

    /// <summary>
    /// The configuration parser, default is json
    /// </summary>
    public INacosConfigurationParser NacosConfigurationParser { get; set; }

    public NacosV2ConfigurationSource(INacosConfigService client)
    {
        Client = client;
    }

    /// <summary>
    /// Build the provider
    /// </summary>
    /// <param name="builder">builder</param>
    /// <returns>IConfigurationProvider</returns>
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        return new NacosV2ConfigurationProvider(this, Client);
    }

    public string GetNamespace()
    {
        // breaking change here after 1.3.3 release
        // do not use tenant any more!!!!
        if (Namespace.IsNotNullOrWhiteSpace())
        {
            return Namespace;
        }
        else
        {
            return string.Empty;
        }
    }

    internal Action<NacosSdkOptions> GetNacosSdkOptions()
    {
        Action<NacosSdkOptions> action = (x) =>
        {
            x.ServerAddresses = this.ServerAddresses;
            x.Namespace = this.Namespace;
            x.AccessKey = this.AccessKey;
            x.ContextPath = this.ContextPath;
            x.EndPoint = this.EndPoint;
            x.DefaultTimeOut = this.DefaultTimeOut;
            x.SecretKey = this.SecretKey;
            x.Password = this.Password;
            x.UserName = this.UserName;
            x.ListenInterval = this.ListenInterval;
            x.ConfigUseRpc = this.ConfigUseRpc;
            x.ConfigFilterAssemblies = this.ConfigFilterAssemblies;
            x.ConfigFilterExtInfo = this.ConfigFilterExtInfo;
        };

        return action;
    }
}