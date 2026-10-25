// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'dnsServers': one item per DNS server of an interface
    /// (dns-proxy.dnsServers), without the fec0:0:0:ffff::1..3 stubs (D-007)
    /// and without repeats on the same interface. With:
    /// - interfaceIsTunnel, interfaceUp: from fact 'adapters';
    /// - viaTunnel: the route to the server goes through a tunnel
    ///   (connectivity.dnsServers[].viaInterfaceIndex - known for the servers
    ///   'connectivity' tested; null otherwise, never guessed);
    /// - responds: the server answered the 'connectivity' check (null if not
    ///   tested);
    /// - fullTunnel: external IPv4 goes through a tunnel (fact 'tunnelCoverage');
    /// - nrptCatchAll: the NRPT has a rule for "." - all names go to its servers.
    /// A DNS leak: a full tunnel, and a server of a physical interface is
    /// reachable past the tunnel. Requires 'dns-proxy'.
    /// </summary>
    public sealed class DnsServerFacts : IFactProvider
    {
        public string Name => "dnsServers";

        public FactSet Build(FactContext context)
        {
            string reason;
            var dns = context.ModuleData("dns-proxy", out reason);
            if (dns == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var adapters = context.Get("adapters");
            if (!adapters.Available) fact.Limitations.Add("tunnel-detection-unavailable:" + adapters.UnavailableReason);

            var coverage = context.Get("tunnelCoverage");
            bool? fullTunnel = null;
            if (coverage.Available && coverage.Items.Count > 0) fullTunnel = JsonValue.AsBool(coverage.Items[0].Values["ipv4ViaTunnel"]);
            else fact.Limitations.Add("full-tunnel-unknown:" + coverage.UnavailableReason);

            bool? nrptCatchAll = null;
            var nrpt = JsonValue.AsList(JsonValue.Get(dns, "nrpt"));
            if (nrpt != null)
            {
                nrptCatchAll = false;
                foreach (var rule in nrpt)
                {
                    if (JsonValue.AsString(JsonValue.Get(rule, "namespace")) == ".") nrptCatchAll = true;
                }
            }

            string connectivityReason;
            var connectivity = context.ModuleData("connectivity", out connectivityReason);
            var tested = JsonValue.GetList(connectivity, "dnsServers");

            var servers = JsonValue.GetList(dns, "dnsServers");
            for (var i = 0; i < servers.Count; i++)
            {
                var entry = servers[i];
                var index = JsonValue.AsInt(JsonValue.Get(entry, "interfaceIndex"));
                var adapter = AdapterFacts.Find(adapters, index);
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var raw in JsonValue.GetList(entry, "serverAddresses"))
                {
                    var address = Addresses.StripZone(JsonValue.AsString(raw));
                    if (address == null || Addresses.IsWindowsDnsStub(address) || !seen.Add(address)) continue;
                    var evidence = new List<string> { "dns-proxy.dnsServers[" + i + "]" };
                    bool? responds = null, viaTunnel = null;
                    int? via = null;
                    for (var j = 0; j < tested.Count; j++)
                    {
                        var t = tested[j];
                        if (!Addresses.Same(JsonValue.AsString(JsonValue.Get(t, "address")), address)) continue;
                        if (JsonValue.AsInt(JsonValue.Get(t, "interfaceIndex")) != index || JsonValue.AsBool(JsonValue.Get(t, "tested")) != true) continue;
                        responds = JsonValue.AsBool(JsonValue.Get(t, "responds"));
                        via = JsonValue.AsInt(JsonValue.Get(t, "viaInterfaceIndex"));
                        viaTunnel = AdapterFacts.IsTunnel(adapters, via);
                        evidence.Add("connectivity.dnsServers[" + j + "]");
                        break;
                    }
                    // Under a full tunnel an untested server of a physical interface may leak unseen.
                    var limitation = "dns-path-not-tested:" + (connectivity == null ? connectivityReason : "server-not-tested");
                    if (fullTunnel == true && viaTunnel == null && adapter != null && !(bool)adapter.Values["isTunnel"] && !fact.Limitations.Contains(limitation))
                        fact.Limitations.Add(limitation);
                    fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["address"] = address,
                        ["family"] = JsonValue.AsString(JsonValue.Get(entry, "addressFamily")),
                        ["interfaceIndex"] = index,
                        ["interfaceAlias"] = JsonValue.AsString(JsonValue.Get(entry, "interfaceAlias")),
                        ["interfaceIsTunnel"] = adapter == null ? (bool?)null : (bool)adapter.Values["isTunnel"],
                        ["interfaceUp"] = adapter == null ? (bool?)null : string.Equals(JsonValue.AsString(adapter.Values["status"]), "Up", StringComparison.OrdinalIgnoreCase),
                        ["addressClass"] = Addresses.Class(address),
                        ["viaInterfaceIndex"] = via,
                        ["viaTunnel"] = viaTunnel,
                        ["responds"] = responds,
                        ["fullTunnel"] = fullTunnel,
                        ["nrptCatchAll"] = nrptCatchAll,
                    }, evidence));
                }
            }
            return fact;
        }
    }
}
