﻿namespace Nacos.Remote.Requests;

public abstract class AbstractNamingRequest : CommonRequest
{
    [System.Text.Json.Serialization.JsonPropertyName("namespace")]
    public string Namespace { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("serviceName")]
    public string ServiceName { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("groupName")]
    public string GroupName { get; set; }

    public AbstractNamingRequest(string @namespace, string serviceName, string groupName)
    {
        Namespace = @namespace;
        ServiceName = serviceName;
        GroupName = groupName;
    }
}