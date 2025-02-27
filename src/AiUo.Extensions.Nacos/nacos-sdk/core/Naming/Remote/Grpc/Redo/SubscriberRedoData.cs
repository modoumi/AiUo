﻿namespace Nacos.Naming.Remote.Grpc.Redo;

public class SubscriberRedoData : RedoData<string>
{
    public SubscriberRedoData(string serviceName, string groupName)
        : base(serviceName, groupName)
    {
    }

    /// <summary>
    /// Build a new RedoData for subscribers.
    /// </summary>
    /// <param name="serviceName">service name for redo data</param>
    /// <param name="groupName">group name for redo data</param>
    /// <param name="clusters">clusters for redo data</param>
    /// <returns>new RedoData for subscribers</returns>
    public static SubscriberRedoData Build(string serviceName, string groupName, string clusters)
    {
        var result = new SubscriberRedoData(serviceName, groupName)
        {
            Data = clusters
        };
        return result;
    }
}