﻿namespace Nacos.Remote.Responses;

public class SubscribeServiceResponse : CommonResponse
{
    [System.Text.Json.Serialization.JsonPropertyName("serviceInfo")]
    public Naming.Dtos.ServiceInfo ServiceInfo { get; set; }

    public override string GetRemoteType() => RemoteRequestType.Resp_Naming_SubscribeService;
}