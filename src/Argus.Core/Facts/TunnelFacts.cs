// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'tunnels': tunnel adapters (fact 'adapters') that are up or carry
    /// routes, with whether they capture the default route: 0.0.0.0/0 or a
    /// half of it (0.0.0.0/1, 128.0.0.0/1 - OpenVPN def1), ::/0 or ::/1,
    /// 8000::/1. Two tunnels capturing the default route fight for all
    /// traffic. A tunnel adapter without such routes (WAN Miniport, a mesh
    /// network without an exit node) only carries its own prefixes.
    /// Requires 'routing' and fact 'adapters'.
    /// </summary>
    public sealed class TunnelFacts : IFactProvider
    {
        private static readonly HashSet<string> DefaultIPv4 = new HashSet<string>(StringComparer.Ordinal) { "0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1" };
        private static readonly HashSet<string> DefaultIPv6 = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "::/0", "::/1", "8000::/1" };

        public string Name => "tunnels";

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var adapters = context.Get("adapters");
            if (!adapters.Available) return FactSet.Unavailable(Name, adapters.UnavailableReason);
            var fact = FactSet.Create(Name);
            fact.Limitations.AddRange(adapters.Limitations);

            var connected = Connected(routing);
            int path4, path6;
            var selected4 = Selection(routing, "externalIPv4", out path4);
            var selected6 = Selection(routing, "externalIPv6", out path6);
            var routes = JsonValue.GetList(routing, "routes");

            foreach (var adapter in adapters.Items)
            {
                if (!(bool)adapter.Values["isTunnel"]) continue;
                var index = JsonValue.AsInt(adapter.Values["interfaceIndex"]);
                if (index == null) continue;
                var evidence = new List<string>(adapter.Evidence);
                bool captures4 = false, captures6 = false, hasRoutes = false;
                for (var i = 0; i < routes.Count; i++)
                {
                    var r = routes[i];
                    if (JsonValue.AsInt(JsonValue.Get(r, "interfaceIndex")) != index) continue;
                    var family = JsonValue.AsString(JsonValue.Get(r, "addressFamily"));
                    bool isConnected;
                    if (connected.TryGetValue(index + "/" + family, out isConnected) && !isConnected) continue;
                    hasRoutes = true;
                    var prefix = JsonValue.AsString(JsonValue.Get(r, "destinationPrefix")) ?? "";
                    var isDefault = family == "IPv6" ? DefaultIPv6.Contains(prefix) : DefaultIPv4.Contains(prefix);
                    if (!isDefault) continue;
                    if (family == "IPv6") captures6 = true; else captures4 = true;
                    evidence.Add("routing.routes[" + i + "]");
                }
                var status = JsonValue.AsString(adapter.Values["status"]);
                if (!hasRoutes && !string.Equals(status, "Up", StringComparison.OrdinalIgnoreCase)) continue;
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["name"] = adapter.Values["name"],
                    ["interfaceIndex"] = index,
                    ["description"] = adapter.Values["description"],
                    ["clientId"] = adapter.Values["clientId"],
                    ["clientKind"] = adapter.Values["clientKind"],
                    ["status"] = status,
                    ["capturesDefaultIPv4"] = captures4,
                    ["capturesDefaultIPv6"] = captures6,
                    ["selectedIPv4"] = selected4 == index,
                    ["selectedIPv6"] = selected6 == index,
                }, evidence));
            }
            return fact;
        }

        /// <summary>Interface index + family ("3/IPv4") -> connected, from routing.interfaces.</summary>
        internal static Dictionary<string, bool> Connected(IDictionary<string, object> routing)
        {
            var connected = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (var itf in JsonValue.GetList(routing, "interfaces"))
            {
                var key = JsonValue.Get(itf, "interfaceIndex") + "/" + JsonValue.AsString(JsonValue.Get(itf, "addressFamily"));
                connected[key] = JsonValue.AsString(JsonValue.Get(itf, "connectionState")) == "Connected";
            }
            return connected;
        }

        /// <summary>Interface Windows selects for a routeSelection kind; path = its index in routeSelection, -1 if absent.</summary>
        internal static int? Selection(IDictionary<string, object> routing, string kind, out int path)
        {
            bool? reachable;
            return Selection(routing, kind, out path, out reachable);
        }

        internal static int? Selection(IDictionary<string, object> routing, string kind, out int path, out bool? reachable)
        {
            var list = JsonValue.GetList(routing, "routeSelection");
            for (var i = 0; i < list.Count; i++)
            {
                if (JsonValue.AsString(JsonValue.Get(list[i], "kind")) != kind) continue;
                path = i;
                reachable = JsonValue.AsBool(JsonValue.Get(list[i], "reachable"));
                return JsonValue.AsInt(JsonValue.Get(list[i], "interfaceIndex"));
            }
            path = -1;
            reachable = null;
            return null;
        }
    }
}
