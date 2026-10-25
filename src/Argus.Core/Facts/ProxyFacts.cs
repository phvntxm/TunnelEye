// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'proxies': configured proxies (user and machine Internet
    /// Settings, WinHTTP) from 'dns-proxy', with:
    /// - effective: the setting is in force - user: ProxyEnable; machine:
    ///   ProxyEnable and the ProxySettingsPerUser = 0 policy (otherwise HKLM is
    ///   not used); WinHTTP: not direct;
    /// - tcpStatus: the TCP check of 'connectivity' (open, refused, timeout,
    ///   error; null if not tested);
    /// - listening: for loopback hosts, whether 'connections' has a listener on
    ///   the port (null if unknown).
    /// Requires 'dns-proxy'. User settings are not checked when the snapshot
    /// was taken under another account's elevation (D-015).
    /// </summary>
    public sealed class ProxyFacts : IFactProvider
    {
        public string Name => "proxies";

        public FactSet Build(FactContext context)
        {
            string reason;
            var dns = context.ModuleData("dns-proxy", out reason);
            if (dns == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);

            string connectivityReason, connectionsReason;
            var connectivity = context.ModuleData("connectivity", out connectivityReason);
            var connections = context.ModuleData("connections", out connectionsReason);
            if (connectivity == null && connections == null) fact.Limitations.Add("reachability-unknown:" + connectivityReason + "," + connectionsReason);

            var proxy = JsonValue.Get(dns, "proxy");
            var sources = new List<Tuple<string, string, bool, string>>();
            if (context.Snapshot.ElevatedAsOtherUser) fact.Limitations.Add("elevated-as-other-user:user-proxy-not-checked");
            else
            {
                var user = JsonValue.Get(proxy, "user");
                sources.Add(Tuple.Create("user", JsonValue.AsString(JsonValue.Get(user, "proxyServer")), JsonValue.AsBool(JsonValue.Get(user, "proxyEnable")) == true, "dns-proxy.proxy.user"));
            }
            var machine = JsonValue.Get(proxy, "machine");
            var perUser = JsonValue.AsInt(JsonValue.Get(machine, "proxySettingsPerUser"));
            sources.Add(Tuple.Create("machine", JsonValue.AsString(JsonValue.Get(machine, "proxyServer")),
                JsonValue.AsBool(JsonValue.Get(machine, "proxyEnable")) == true && perUser == 0, "dns-proxy.proxy.machine"));
            var winhttp = JsonValue.Get(proxy, "winhttp");
            sources.Add(Tuple.Create("winhttp", JsonValue.AsString(JsonValue.Get(winhttp, "proxyServer")),
                JsonValue.AsBool(JsonValue.Get(winhttp, "direct")) == false, "dns-proxy.proxy.winhttp"));

            var tested = JsonValue.GetList(connectivity, "proxies");
            var listeners = JsonValue.GetList(connections, "tcpListeners");

            foreach (var source in sources)
            {
                foreach (var entry in ParseProxyServer(source.Item2))
                {
                    var evidence = new List<string> { source.Item4 };
                    string tcpStatus = null;
                    for (var i = 0; i < tested.Count; i++)
                    {
                        var t = tested[i];
                        if (JsonValue.AsString(JsonValue.Get(t, "source")) != source.Item1) continue;
                        if (!string.Equals(JsonValue.AsString(JsonValue.Get(t, "host")), entry.Host, StringComparison.OrdinalIgnoreCase)) continue;
                        if (JsonValue.AsInt(JsonValue.Get(t, "port")) != entry.Port) continue;
                        if (JsonValue.AsBool(JsonValue.Get(t, "tested")) != true) continue;
                        tcpStatus = JsonValue.AsString(JsonValue.Get(t, "status"));
                        evidence.Add("connectivity.proxies[" + i + "]");
                        break;
                    }
                    var loopback = IsLoopback(entry.Host);
                    bool? listening = null;
                    if (loopback && entry.Port != null && connections != null)
                    {
                        listening = false;
                        for (var i = 0; i < listeners.Count; i++)
                        {
                            var l = listeners[i];
                            if (JsonValue.AsInt(JsonValue.Get(l, "localPort")) != entry.Port) continue;
                            var address = JsonValue.AsString(JsonValue.Get(l, "localAddress"));
                            if (address == "127.0.0.1" || address == "0.0.0.0" || address == "::" || address == "::1")
                            {
                                listening = true;
                                evidence.Add("connections.tcpListeners[" + i + "]");
                                break;
                            }
                        }
                    }
                    fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["source"] = source.Item1,
                        ["effective"] = source.Item3,
                        ["scheme"] = entry.Scheme,
                        ["host"] = entry.Host,
                        ["port"] = entry.Port,
                        ["isLoopback"] = loopback,
                        ["tcpStatus"] = tcpStatus,
                        ["listening"] = listening,
                    }, evidence));
                }
            }
            return fact;
        }

        internal static bool IsLoopback(string host)
        {
            if (host == null) return false;
            return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || host == "::1" || host.StartsWith("127.", StringComparison.Ordinal);
        }

        internal sealed class ProxyEntry
        {
            public string Scheme;
            public string Host;
            public int? Port;
        }

        /// <summary>
        /// ProxyServer values: "host:port", "http=host:port;https=host:port",
        /// "http://host:port", "socks=host:port", "[::1]:8080" (credentials are
        /// already stripped by the collector). Same rules as in 'connectivity'.
        /// </summary>
        internal static List<ProxyEntry> ParseProxyServer(string value)
        {
            var result = new List<ProxyEntry>();
            if (string.IsNullOrWhiteSpace(value)) return result;
            foreach (var rawPart in value.Split(';'))
            {
                var p = rawPart.Trim();
                if (p.Length == 0) continue;
                string scheme = null;
                var m = Regex.Match(p, @"^([A-Za-z]+)=(.*)$");
                if (m.Success) { scheme = m.Groups[1].Value.ToLowerInvariant(); p = m.Groups[2].Value.Trim(); }
                m = Regex.Match(p, @"^([A-Za-z][A-Za-z0-9+.-]*)://(.*)$");
                if (m.Success) { if (scheme == null) scheme = m.Groups[1].Value.ToLowerInvariant(); p = m.Groups[2].Value; }
                p = p.TrimEnd('/');
                var at = p.LastIndexOf('@');
                if (at >= 0) p = p.Substring(at + 1);
                string host = null;
                int? port = null;
                m = Regex.Match(p, @"^\[([^\]]+)\](?::(\d+))?$");
                if (m.Success) { host = m.Groups[1].Value; if (m.Groups[2].Success) port = int.Parse(m.Groups[2].Value); }
                else
                {
                    m = Regex.Match(p, @"^([^:]+):(\d+)$");
                    if (m.Success) { host = m.Groups[1].Value; port = int.Parse(m.Groups[2].Value); }
                    else if (p.IndexOf(':') < 0) host = p;
                }
                if (!string.IsNullOrEmpty(host)) result.Add(new ProxyEntry { Scheme = scheme, Host = host, Port = port });
            }
            return result;
        }
    }
}
