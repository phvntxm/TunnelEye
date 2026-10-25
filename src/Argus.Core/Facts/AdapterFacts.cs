// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'adapters': network adapters with a tunnel flag. A tunnel is an
    /// adapter a VPN client, proxy tunnel or tunnel driver claims in the 'vpn'
    /// module, or one whose description or component id looks like a tunnel.
    /// Requires 'adapters'; 'vpn' is optional (without it the tunnel flag
    /// relies on the description only, which is a limitation).
    /// </summary>
    public sealed class AdapterFacts : IFactProvider
    {
        private static readonly Regex TunnelPattern = new Regex(
            @"tap-windows|tap0901|wintun|wireguard|ovpn|openvpn|\bvpn\b|vpn\s|\btun\b|-tun\b|wan miniport|\bppp\b|tunnel",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public string Name => "adapters";

        public FactSet Build(FactContext context)
        {
            string reason;
            var data = context.ModuleData("adapters", out reason);
            if (data == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);

            // Interface index -> claiming client, from the vpn module.
            var claims = new Dictionary<int, IDictionary<string, object>>();
            string vpnReason;
            var vpn = context.ModuleData("vpn", out vpnReason);
            if (vpn == null) fact.Limitations.Add("tunnel-detection-by-description:" + vpnReason);
            else
            {
                foreach (var client in JsonValue.GetList(vpn, "clients"))
                {
                    var kind = JsonValue.AsString(JsonValue.Get(client, "kind"));
                    if (kind == "dpi-bypass") continue;
                    foreach (var adapter in JsonValue.GetList(client, "adapters"))
                    {
                        var index = JsonValue.AsInt(JsonValue.Get(adapter, "interfaceIndex"));
                        if (index != null && !claims.ContainsKey(index.Value)) claims[index.Value] = JsonValue.AsObject(client);
                    }
                }
            }

            var adapters = JsonValue.GetList(data, "adapters");
            for (var i = 0; i < adapters.Count; i++)
            {
                var a = adapters[i];
                var index = JsonValue.AsInt(JsonValue.Get(a, "interfaceIndex"));
                var description = JsonValue.AsString(JsonValue.Get(a, "interfaceDescription"));
                var componentId = JsonValue.AsString(JsonValue.Get(a, "componentId"));
                IDictionary<string, object> client = null;
                if (index != null) claims.TryGetValue(index.Value, out client);
                var looksLikeTunnel = (description != null && TunnelPattern.IsMatch(description)) || (componentId != null && TunnelPattern.IsMatch(componentId));
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["name"] = JsonValue.AsString(JsonValue.Get(a, "name")),
                    ["interfaceIndex"] = index,
                    ["description"] = description,
                    ["componentId"] = componentId,
                    ["status"] = JsonValue.AsString(JsonValue.Get(a, "status")),
                    ["virtual"] = JsonValue.AsBool(JsonValue.Get(a, "virtual")),
                    ["isTunnel"] = client != null || looksLikeTunnel,
                    ["clientId"] = client != null ? JsonValue.AsString(JsonValue.Get(client, "id")) : null,
                    ["clientKind"] = client != null ? JsonValue.AsString(JsonValue.Get(client, "kind")) : null,
                }, new[] { "adapters.adapters[" + i + "]" }));
            }
            return fact;
        }

        /// <summary>Tunnel flag by interface index from a built 'adapters' fact; null if unknown.</summary>
        internal static bool? IsTunnel(FactSet adapters, int? interfaceIndex)
        {
            if (adapters == null || !adapters.Available || interfaceIndex == null) return null;
            foreach (var item in adapters.Items)
            {
                if (JsonValue.AsInt(item.Values["interfaceIndex"]) == interfaceIndex) return (bool)item.Values["isTunnel"];
            }
            return null;
        }
    }
}
