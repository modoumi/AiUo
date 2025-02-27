﻿using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.IO;
using Nacos.Naming.Backups;
using Nacos.Naming.Dtos;
using Nacos.Naming.Event;
using Nacos.Naming.Utils;
using Nacos.Utils;
using Microsoft.Extensions.Options;
using Nacos.Common;
using Nacos.Logging;

namespace Nacos.Naming.Cache;

public class ServiceInfoHolder : IDisposable
{
    private static readonly string FILE_PATH_NACOS = "nacos";
    private static readonly string FILE_PATH_NAMING = "naming";

    private readonly ILogger _logger = NacosLogManager.CreateLogger<ServiceInfoHolder>();
    private readonly FailoverReactor _failoverReactor;
    private readonly ConcurrentDictionary<string, Dtos.ServiceInfo> _serviceInfoMap;
    private readonly NacosSdkOptions _options;

    private InstancesChangeNotifier _notifier;
    private string cacheDir = string.Empty;
    private bool _pushEmptyProtection;

    internal ServiceInfoHolder(string namespeceId, NacosSdkOptions options, InstancesChangeNotifier notifier = null)
    {
        _options = options;

        InitCacheDir(namespeceId, _options);

        if (IsLoadCacheAtStart(_options))
        {
            var data = DiskCache.ReadAsync(cacheDir).ConfigureAwait(false).GetAwaiter().GetResult();
            _serviceInfoMap = new ConcurrentDictionary<string, Dtos.ServiceInfo>(data);
        }
        else
        {
            _serviceInfoMap = new ConcurrentDictionary<string, Dtos.ServiceInfo>();
        }

        _failoverReactor = new FailoverReactor(this, cacheDir);
        _pushEmptyProtection = _options.NamingPushEmptyProtection;
    }

    public ServiceInfoHolder(IOptions<NacosSdkOptions> optionsAccs, InstancesChangeNotifier notifier = null)
    {
        _notifier = notifier;
        _options = optionsAccs.Value;

        var @namespace = _options.Namespace.IsNullOrWhiteSpace() ? Constants.DEFAULT_NAMESPACE_ID : _options.Namespace;
        InitCacheDir(@namespace, _options);

        if (IsLoadCacheAtStart(_options))
        {
            var data = DiskCache.ReadAsync(cacheDir).ConfigureAwait(false).GetAwaiter().GetResult();
            _serviceInfoMap = new ConcurrentDictionary<string, Dtos.ServiceInfo>(data);
        }
        else
        {
            _serviceInfoMap = new ConcurrentDictionary<string, Dtos.ServiceInfo>();
        }

        _failoverReactor = new FailoverReactor(this, cacheDir);
        _pushEmptyProtection = _options.NamingPushEmptyProtection;
    }

    private bool IsLoadCacheAtStart(NacosSdkOptions nacosOptions)
    {
        bool loadCacheAtStart = false;
        if (nacosOptions != null && nacosOptions.NamingLoadCacheAtStart.IsNotNullOrWhiteSpace())
        {
            loadCacheAtStart = Convert.ToBoolean(nacosOptions.NamingLoadCacheAtStart);
        }

        return loadCacheAtStart;
    }

    internal Dtos.ServiceInfo ProcessServiceInfo(string json)
    {
        var serviceInfo = json.ToObj<Dtos.ServiceInfo>();
        serviceInfo.JsonFromServer = json;
        return ProcessServiceInfo(serviceInfo);
    }

    internal Dtos.ServiceInfo ProcessServiceInfo(Dtos.ServiceInfo serviceInfo)
    {
        var serviceKey = serviceInfo.GetKey();

        if (serviceKey.IsNullOrWhiteSpace()) return null;

        _serviceInfoMap.TryGetValue(serviceKey, out var oldService);

        // empty or error push, just ignore
        if (IsEmptyOrErrorPush(serviceInfo)) return oldService;

        _serviceInfoMap.AddOrUpdate(serviceKey, serviceInfo, (x, y) => serviceInfo);

        bool changed = IsChangedServiceInfo(oldService, serviceInfo);

        if (serviceInfo.JsonFromServer.IsNullOrWhiteSpace())
        {
            serviceInfo.JsonFromServer = serviceInfo.ToJsonString();
        }

        if (changed)
        {
            _logger?.LogInformation("current ips:({0}) service: {1} -> {2}", serviceInfo.IpCount(), serviceInfo.GetKey(), serviceInfo.Hosts.ToJsonString());

            if (_notifier != null)
            {
                var @event = new InstancesChangeEvent(serviceInfo.Name, serviceInfo.GroupName, serviceInfo.Clusters, serviceInfo.Hosts);

                _notifier.OnEvent(@event);
            }

            DiskCache.WriteAsync(serviceInfo, cacheDir)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }

        return serviceInfo;
    }

    private bool IsEmptyOrErrorPush(Dtos.ServiceInfo serviceInfo)
        => serviceInfo.Hosts == null || (_pushEmptyProtection && !serviceInfo.Validate());

    private bool IsChangedServiceInfo(Dtos.ServiceInfo oldService, Dtos.ServiceInfo newService)
    {
        if (oldService == null)
        {
            _logger?.LogInformation("init new ips({0}) service: {1} -> {2}", newService.IpCount(), newService.GetKey(), newService.Hosts.ToJsonString());
            return true;
        }

        if (oldService.LastRefTime > newService.LastRefTime)
        {
            _logger?.LogWarning("out of date data received, old-t: {0}, new-t: {1}", oldService.LastRefTime, newService.LastRefTime);
            return false;
        }

        bool changed = false;

        var oldHostMap = oldService.Hosts.ToDictionary(x => x.ToInetAddr());
        var newHostMap = newService.Hosts.ToDictionary(x => x.ToInetAddr());

        var modHosts = newHostMap.Where(x => oldHostMap.ContainsKey(x.Key) && !x.Value.ToString().Equals(oldHostMap[x.Key].ToString()))
            .Select(x => x.Value).ToList();
        var newHosts = newHostMap.Where(x => !oldHostMap.ContainsKey(x.Key))
            .Select(x => x.Value).ToList();
        var removeHosts = oldHostMap.Where(x => !newHostMap.ContainsKey(x.Key))
            .Select(x => x.Value).ToList();

        if (newHosts.Count > 0)
        {
            changed = true;
            _logger?.LogInformation(
                "new ips ({0}) service: {1} -> {2}",
                newHosts.Count(),
                newService.GetKey(),
                newHosts.ToJsonString());
        }

        if (removeHosts.Count > 0)
        {
            changed = true;
            _logger?.LogInformation(
                "removed ips ({0}) service: {1} -> {2}",
                removeHosts.Count(),
                newService.GetKey(),
                removeHosts.ToJsonString());
        }

        if (modHosts.Count > 0)
        {
            changed = true;
            _logger?.LogInformation(
                "modified ips ({0}) service: {1} -> {2}",
                modHosts.Count(),
                newService.GetKey(),
                modHosts.ToJsonString());
        }

        return changed;
    }

    internal ConcurrentDictionary<string, Dtos.ServiceInfo> GetServiceInfoMap() => _serviceInfoMap;

    private void InitCacheDir(string @namespace, NacosSdkOptions options)
    {
        var jmSnapshotPath = EnvUtil.GetEnvValue("JM.SNAPSHOT.PATH");

        string namingCacheRegistryDir = string.Empty;
        if (options.NamingCacheRegistryDir.IsNotNullOrWhiteSpace())
        {
            namingCacheRegistryDir = options.NamingCacheRegistryDir;
        }

        if (jmSnapshotPath.IsNotNullOrWhiteSpace())
        {
            cacheDir = Path.Combine(jmSnapshotPath, FILE_PATH_NACOS, namingCacheRegistryDir, FILE_PATH_NAMING, @namespace);
        }
        else
        {
            cacheDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), FILE_PATH_NACOS, namingCacheRegistryDir, FILE_PATH_NAMING, @namespace);
        }
    }

    internal Dtos.ServiceInfo GetServiceInfo(string serviceName, string groupName, string clusters)
    {
        var flag = _failoverReactor.IsFailoverSwitch();
        _logger?.LogDebug("failover-mode:{0}", flag);
        string groupedServiceName = NamingUtils.GetGroupedName(serviceName, groupName);
        string key = ServiceInfo.GetKey(groupedServiceName, clusters);

        if (flag)
        {
            return _failoverReactor.GetService(key);
        }

        return _serviceInfoMap.TryGetValue(key, out var serviceInfo) ? serviceInfo : null;
    }

    public void Dispose()
    {
        _logger?.LogInformation("{0} do shutdown begin", nameof(ServiceInfoHolder));
        _failoverReactor?.Dispose();
        _logger?.LogInformation("{0} do shutdown stop", nameof(ServiceInfoHolder));
    }
}