// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>External tests of 'connectivity' (D-002): without consent the facts are unavailable, not empty.</summary>
    internal static class ExternalTests
    {
        internal static object Section(FactContext context, out string reason)
        {
            var connectivity = context.ModuleData("connectivity", out reason);
            if (connectivity == null) return null;
            var external = JsonValue.Get(connectivity, "external");
            if (external == null) reason = "external-not-allowed";
            return external;
        }
    }

    /// <summary>
    /// Fact 'traces': one item per trace route of the external tests
    /// (connectivity.external.trace). repeatedAddresses counts hop addresses
    /// that come back after a different hop (A, B, A): a packet going in a
    /// circle - a routing loop. A router answering two TTLs in a row is not a
    /// repeat. Only a trace shows a loop: without external tests the fact is
    /// unavailable (reply to plan 006, item 6). Requires 'connectivity'.
    /// </summary>
    public sealed class TraceFacts : IFactProvider
    {
        public string Name => "traces";

        public FactSet Build(FactContext context)
        {
            string reason;
            var external = ExternalTests.Section(context, out reason);
            if (external == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var traces = JsonValue.GetList(external, "trace");
            for (var i = 0; i < traces.Count; i++)
            {
                var t = traces[i];
                var hops = JsonValue.GetList(t, "hops");
                var ttls = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
                foreach (var hop in hops)
                {
                    var address = JsonValue.AsString(JsonValue.Get(hop, "address"));
                    var ttl = JsonValue.AsInt(JsonValue.Get(hop, "ttl"));
                    if (address == null || ttl == null) continue;
                    List<int> list;
                    if (!ttls.TryGetValue(address, out list)) ttls[address] = list = new List<int>();
                    list.Add(ttl.Value);
                }
                var repeated = ttls.Values.Count(list => { list.Sort(); for (var k = 1; k < list.Count; k++) if (list[k] - list[k - 1] >= 2) return true; return false; });
                var status = JsonValue.AsString(JsonValue.Get(t, "status"));
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["target"] = JsonValue.AsString(JsonValue.Get(t, "target")),
                    ["status"] = status,
                    ["reached"] = status == "reached",
                    ["hops"] = hops.Count,
                    ["repeatedAddresses"] = repeated,
                }, new[] { "connectivity.external.trace[" + i + "]" }));
            }
            return fact;
        }
    }

    /// <summary>
    /// Fact 'dnsAnswers': one item per name of the external DNS comparison
    /// (connectivity.external.dns), over the DNS servers - the system resolver
    /// is left out: it includes hosts and DoH, which have their own rules.
    /// - sinkholeServers: servers that answered with 0.0.0.0, ::, 127.x or ::1;
    /// - nxdomainServers: servers that said the name does not exist;
    /// - answeredServers: servers that gave a real address.
    /// "Does not exist" from some servers while others answer, or a sinkhole
    /// for a neutral name, is a DNS spoofing sign. Different address sets alone
    /// are not (CDN, load balancing). Requires 'connectivity'.
    /// </summary>
    public sealed class DnsAnswerFacts : IFactProvider
    {
        public string Name => "dnsAnswers";

        public FactSet Build(FactContext context)
        {
            string reason;
            var external = ExternalTests.Section(context, out reason);
            if (external == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var names = JsonValue.GetList(external, "dns");
            for (var i = 0; i < names.Count; i++)
            {
                int servers = 0, sinkhole = 0, nxdomain = 0, answered = 0, failed = 0;
                foreach (var r in JsonValue.GetList(names[i], "results"))
                {
                    if (JsonValue.AsString(JsonValue.Get(r, "source")) == "system") continue;
                    var status = JsonValue.AsString(JsonValue.Get(r, "status"));
                    if (status == "skipped") continue;
                    servers++;
                    if (status == "nxdomain") nxdomain++;
                    else if (status == "timeout" || status == "error") failed++;
                    else if (status == "answer")
                    {
                        var classes = JsonValue.GetList(r, "addresses").Select(a => Addresses.Class(JsonValue.AsString(a))).ToList();
                        if (classes.Any(c => c == "unspecified" || c == "loopback")) sinkhole++;
                        else if (classes.Count > 0) answered++;
                    }
                }
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["name"] = JsonValue.AsString(JsonValue.Get(names[i], "name")),
                    ["servers"] = servers,
                    ["sinkholeServers"] = sinkhole,
                    ["nxdomainServers"] = nxdomain,
                    ["answeredServers"] = answered,
                    ["failedServers"] = failed,
                }, new[] { "connectivity.external.dns[" + i + "]" }));
            }
            return fact;
        }
    }

    /// <summary>
    /// Fact 'snapshotInfo': one item about how the snapshot was taken -
    /// elevated, elevatedAsOtherUser (D-015), externalAllowed (D-002). For
    /// the "Info" findings: what the report could not check and why.
    /// </summary>
    public sealed class SnapshotInfoFacts : IFactProvider
    {
        public string Name => "snapshotInfo";

        public FactSet Build(FactContext context)
        {
            var s = context.Snapshot;
            var fact = FactSet.Create(Name);
            fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["elevated"] = s.Elevated,
                ["elevatedAsOtherUser"] = JsonValue.AsBool(JsonValue.Get(JsonValue.Get(s.Root, "host"), "elevatedAsOtherUser")),
                ["externalAllowed"] = JsonValue.AsBool(JsonValue.Get(s.Root, "externalAllowed")),
            }, new[] { "host", "externalAllowed" }));
            return fact;
        }
    }
}
