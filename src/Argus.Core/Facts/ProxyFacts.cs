// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
                    var effective = Effective(context, proxy, source.Item1);
                    if (effective == null) fact.Limitations.Add("proxy-scope-unknown:" + source.Item1);
                    string tcpStatus = null;
                    string process = null;
                    int? processId = null;
                    // Why the TCP check is missing, for the limitation: the module's
                    // reason (externalNotAllowed, noPort, budget) or the module state.
                    string notTestedReason = connectivity == null ? connectivityReason : "not-in-connectivity";
                    for (var i = 0; i < tested.Count; i++)
                    {
                        var t = tested[i];
                        if (JsonValue.AsString(JsonValue.Get(t, "source")) != source.Item1) continue;
                        if (!string.Equals(JsonValue.AsString(JsonValue.Get(t, "host")), entry.Host, StringComparison.OrdinalIgnoreCase)) continue;
                        if (JsonValue.AsInt(JsonValue.Get(t, "port")) != entry.Port) continue;
                        if (JsonValue.AsBool(JsonValue.Get(t, "tested")) != true)
                        {
                            notTestedReason = JsonValue.AsString(JsonValue.Get(t, "reason")) ?? "not-tested";
                            continue;
                        }
                        tcpStatus = JsonValue.AsString(JsonValue.Get(t, "status"));
                        evidence.Add("connectivity.proxies[" + i + "]");
                        break;
                    }
                    var loopback = IsLoopback(entry.Host);
                    bool? listening = null;
                    if (loopback && entry.Port != null && connections != null)
                    {
                        if (SectionEvidence.Complete(context.Snapshot, "connections", "tcpListeners", "Get-NetUDPEndpoint", "Get-Process") &&
                            listeners.All(ValidListener))
                        {
                            listening = false;
                            evidence.Add("connections.tcpListeners");
                        }
                        for (var i = 0; i < listeners.Count; i++)
                        {
                            var l = listeners[i];
                            if (JsonValue.AsInt(JsonValue.Get(l, "localPort")) != entry.Port) continue;
                            if (ServesHost(JsonValue.AsString(JsonValue.Get(l, "localAddress")), entry.Host))
                            {
                                listening = true;
                                process = JsonValue.AsString(JsonValue.Get(l, "process"));
                                processId = JsonValue.AsInt(JsonValue.Get(l, "processId"));
                                evidence.Add("connections.tcpListeners[" + i + "]");
                                break;
                            }
                        }
                    }
                    // An effective proxy whose reachability is unknown is not "fine":
                    // the rule stays notFound, but the gap is reported.
                    if (effective != false && tcpStatus == null && listening == null)
                        fact.Limitations.Add("proxy-not-tested:" + source.Item1 + ":" + notTestedReason);
                    fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["source"] = source.Item1,
                        ["effective"] = effective,
                        ["scheme"] = entry.Scheme,
                        ["host"] = entry.Host,
                        ["port"] = entry.Port,
                        ["isLoopback"] = loopback,
                        ["tcpStatus"] = tcpStatus,
                        ["listening"] = listening,
                        ["process"] = process,
                        ["processId"] = processId,
                    }, evidence));
                }
            }
            return fact;
        }

        // Effective means the manual setting applies to its stated system API
        // scope. It never means every request or application uses this proxy.
        private static bool? Effective(FactContext context, object proxy, string source)
        {
            var module = context.Snapshot.Module("dns-proxy");
            if (module.Errors.Any(e => e.Source == null || e.Source.IndexOf("Internet Settings", StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.Source.IndexOf("WinHttp", StringComparison.OrdinalIgnoreCase) >= 0)) return null;
            var settings = JsonValue.Get(proxy, source);
            if (source == "winhttp")
            {
                var direct = JsonValue.AsBool(JsonValue.Get(settings, "direct"));
                return direct == null ? (bool?)null : !direct.Value;
            }
            var perUser = JsonValue.AsInt(JsonValue.Get(JsonValue.Get(proxy, "machine"), "proxySettingsPerUser"));
            if (source == "machine" && perUser != 0 || source == "user" && perUser == 0) return false;
            var enabled = JsonValue.AsBool(JsonValue.Get(settings, "proxyEnable"));
            if (enabled != true) return enabled;
            if (!string.IsNullOrEmpty(JsonValue.AsString(JsonValue.Get(settings, "autoConfigUrl")))) return null;
            if (source == "user")
            {
                var connection = JsonValue.Get(settings, "connectionSettings");
                if (JsonValue.AsBool(JsonValue.Get(connection, "proxyEnabled")) != true ||
                    JsonValue.AsBool(JsonValue.Get(connection, "autoConfigEnabled")) != false ||
                    JsonValue.AsBool(JsonValue.Get(connection, "autoDetect")) != false ||
                    !Equals(JsonValue.Get(connection, "proxyServer"), JsonValue.Get(settings, "proxyServer"))) return null;
            }
            return true;
        }

        /// <summary>A port in 1-65535, or null: a registry value like "host:99999999999" must not throw.</summary>
        internal static int? ParsePort(string text)
        {
            int port;
            if (!int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out port)) return null;
            return port >= 1 && port <= 65535 ? port : (int?)null;
        }

        /// <summary>
        /// Whether a listener on localAddress accepts connections to host. A
        /// socket on '::' is IPv6-only by default in Windows (IPV6_V6ONLY), so
        /// it does not serve 127.0.0.1: an IPv4 host needs the same address or
        /// 0.0.0.0, '::1' needs '::1' or '::', 'localhost' accepts either.
        /// </summary>
        internal static bool ServesHost(string localAddress, string host)
        {
            if (localAddress == null || host == null) return false;
            if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
                return localAddress == "0.0.0.0" || localAddress == "::" || localAddress == "::1" || localAddress.StartsWith("127.", StringComparison.Ordinal);
            IPAddress parsed;
            if (IPAddress.TryParse(localAddress, out parsed)) localAddress = parsed.ToString();
            if (IPAddress.TryParse(host, out parsed)) host = parsed.ToString();
            if (host.IndexOf(':') >= 0) return localAddress == "::" || string.Equals(localAddress, host, StringComparison.OrdinalIgnoreCase);
            return localAddress == "0.0.0.0" || localAddress == host;
        }

        internal static bool IsLoopback(string host)
        {
            if (host == null) return false;
            IPAddress address;
            return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
                IPAddress.TryParse(host, out address) && IPAddress.IsLoopback(address);
        }

        private static bool ValidListener(object listener)
        {
            IPAddress address;
            var port = JsonValue.AsInt(JsonValue.Get(listener, "localPort"));
            return port >= 1 && port <= 65535 && IPAddress.TryParse(JsonValue.AsString(JsonValue.Get(listener, "localAddress")), out address);
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
                if (m.Success) { host = m.Groups[1].Value; if (m.Groups[2].Success) port = ParsePort(m.Groups[2].Value); }
                else
                {
                    m = Regex.Match(p, @"^([^:]+):(\d+)$");
                    if (m.Success) { host = m.Groups[1].Value; port = ParsePort(m.Groups[2].Value); }
                    else if (p.IndexOf(':') < 0) host = p;
                }
                if (!string.IsNullOrEmpty(host)) result.Add(new ProxyEntry { Scheme = scheme, Host = host, Port = port });
            }
            return result;
        }
    }
}
