// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>Broad route overlap is configuration evidence, never proof of a failure.</summary>
    public sealed class TunnelRouteOverlapFacts : IFactProvider
    {
        public string Name => "tunnel-route-overlaps";
        private sealed class Route
        {
            internal int Index, Row, AdapterRow, ClientRow, InterfaceRow;
            internal string Client, Family, Prefix;
        }

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var adapters = context.Get("adapters");
            if (!adapters.Available) return FactSet.Unavailable(Name, adapters.UnavailableReason);
            var fact = FactSet.Create(Name);
            var vpn = context.ModuleData("vpn", out reason);
            if (vpn == null) fact.Limitations.Add("vpn-inventory-unknown:" + reason);
            if (!SectionEvidence.Complete(context.Snapshot, "routing", "routes", "Get-NetNat", "Get-NetNatStaticMapping", "ICS"))
                fact.Limitations.Add("route-inventory-incomplete");
            if (!SectionEvidence.Complete(context.Snapshot, "routing", "interfaces", "Get-NetNat", "Get-NetNatStaticMapping", "ICS"))
                fact.Limitations.Add("interface-state-incomplete");
            if (!SectionEvidence.Complete(context.Snapshot, "adapters", "adapters")) fact.Limitations.Add("adapter-inventory-incomplete");
            if (!SectionEvidence.Complete(context.Snapshot, "vpn", "clients")) fact.Limitations.Add("client-inventory-incomplete");
            var rows = JsonValue.GetList(routing, "routes");
            var interfaces = JsonValue.GetList(routing, "interfaces");
            var clients = JsonValue.GetList(vpn, "clients");
            var candidates = new List<Route>();
            for (var r = 0; r < rows.Count; r++)
            {
                var row = rows[r];
                var family = JsonValue.AsString(JsonValue.Get(row, "addressFamily"));
                var prefix = Prefix(family, JsonValue.AsString(JsonValue.Get(row, "destinationPrefix")));
                if (family != "IPv4" && family != "IPv6" || prefix == null || JsonValue.AsInt(JsonValue.Get(row, "interfaceIndex")) == null)
                { fact.Limitations.Add("route-row-incomplete"); continue; }
                if (!Broad(family, prefix)) continue;
                var index = JsonValue.AsInt(JsonValue.Get(row, "interfaceIndex"));
                var adapter = AdapterFacts.Find(adapters, index);
                if (adapter == null) { fact.Limitations.Add("route-adapter-unknown"); continue; }
                if (!Equals(adapter.Values["isTunnel"], true)) continue;
                var status = JsonValue.AsString(adapter.Values["status"]);
                if (!string.Equals(status, "Up", StringComparison.OrdinalIgnoreCase))
                { if (status == null) fact.Limitations.Add("tunnel-state-unknown"); continue; }
                var stateRows = interfaces.Select((x, i) => new { Value = x, Row = i }).Where(x =>
                    JsonValue.AsInt(JsonValue.Get(x.Value, "interfaceIndex")) == index &&
                    Equals(JsonValue.Get(x.Value, "addressFamily"), family)).ToList();
                if (stateRows.Count != 1 || JsonValue.Get(stateRows[0].Value, "connectionState") == null)
                { fact.Limitations.Add("tunnel-family-state-unknown"); continue; }
                if (!Equals(JsonValue.Get(stateRows[0].Value, "connectionState"), "Connected")) continue;
                // Reject generic components, missing identity metadata and ambiguous
                // claims, including a generic engine also claiming a named client adapter.
                var claims = clients.Select((x, i) => new { Value = x, Row = i }).Where(x =>
                    JsonValue.GetList(x.Value, "adapters").Any(a => JsonValue.AsInt(JsonValue.Get(a, "interfaceIndex")) == index)).ToList();
                if (claims.Count != 1 || !Specific(claims[0].Value))
                { fact.Limitations.Add("tunnel-client-unknown"); continue; }
                var client = JsonValue.AsString(JsonValue.Get(claims[0].Value, "id"));
                candidates.Add(new Route { Index = index.Value, Row = r, AdapterRow = adapters.Items.IndexOf(adapter),
                    ClientRow = claims[0].Row, Client = client, Family = family, Prefix = prefix, InterfaceRow = stateRows[0].Row });
            }
            foreach (var family in candidates.GroupBy(r => r.Family))
            {
                var groups = family.GroupBy(r => r.Client, StringComparer.OrdinalIgnoreCase).OrderBy(g => g.Key, StringComparer.Ordinal).ToList();
                for (int a = 0; a < groups.Count; a++) for (int b = a + 1; b < groups.Count; b++)
                {
                    var prefixes = new HashSet<string>(StringComparer.Ordinal);
                    var participants = new List<Route>();
                    foreach (var left in groups[a]) foreach (var right in groups[b])
                    {
                        var overlap = Intersection(left.Prefix, right.Prefix);
                        if (overlap == null) continue;
                        prefixes.Add(overlap); participants.Add(left); participants.Add(right);
                    }
                    if (prefixes.Count == 0) continue;
                    var evidence = participants.SelectMany(r => new[] { "routing.routes[" + r.Row + "]",
                        "adapters.adapters[" + r.AdapterRow + "]", "vpn.clients[" + r.ClientRow + "]",
                        "routing.interfaces[" + r.InterfaceRow + "]" }).Distinct().ToArray();
                    fact.Items.Add(new FactItem(new Dictionary<string, object>
                    {
                        ["clientAId"] = groups[a].Key, ["clientBId"] = groups[b].Key, ["family"] = family.Key,
                        ["overlapConfirmed"] = true, ["overlapPrefixes"] = prefixes.OrderBy(p => p, StringComparer.Ordinal).ToArray(),
                        ["interfaceIndexesA"] = participants.Where(r => r.Client == groups[a].Key).Select(r => r.Index).Distinct().ToArray(),
                        ["interfaceIndexesB"] = participants.Where(r => r.Client == groups[b].Key).Select(r => r.Index).Distinct().ToArray(),
                    }, evidence));
                }
            }
            var limits = fact.Limitations.Distinct().ToArray();
            fact.Limitations.Clear(); fact.Limitations.AddRange(limits);
            return fact;
        }

        internal static bool Specific(object client)
        {
            var id = JsonValue.AsString(JsonValue.Get(client, "id"));
            var kind = JsonValue.AsString(JsonValue.Get(client, "kind"));
            return !string.IsNullOrWhiteSpace(id) && JsonValue.AsBool(JsonValue.Get(client, "generic")) == false &&
                (kind == "vpn" || kind == "proxy-tunnel") &&
                !new[] { "proxy-core", "wintun", "tap-windows", "windivert" }.Contains(id, StringComparer.OrdinalIgnoreCase);
        }

        private static bool Broad(string family, string prefix) => family == "IPv4"
            ? prefix == "0.0.0.0/0" || prefix == "0.0.0.0/1" || prefix == "128.0.0.0/1"
            : family == "IPv6" && (prefix == "::/0" || prefix == "::/1" || prefix == "8000::/1");

        private static string Prefix(string family, string text)
        {
            var parts = (text ?? "").Split('/');
            IPAddress address; int bits;
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out address) || !int.TryParse(parts[1], out bits)) return null;
            var bytes = address.GetAddressBytes();
            if (family != (bytes.Length == 4 ? "IPv4" : "IPv6") || bits < 0 || bits > bytes.Length * 8) return null;
            for (var bit = bits; bit < bytes.Length * 8; bit++)
                if ((bytes[bit / 8] & (1 << (7 - bit % 8))) != 0) return null;
            return address + "/" + bits;
        }

        // Only the six canonical /0 and /1 prefixes admitted above reach here.
        private static string Intersection(string left, string right) => left == right ? left :
            left.EndsWith("/0", StringComparison.Ordinal) ? right : right.EndsWith("/0", StringComparison.Ordinal) ? left : null;
    }
}
