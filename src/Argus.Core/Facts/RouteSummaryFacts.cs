// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'routeSummary': one item per address family about the default
    /// routes. 'gateways' counts default routes with a next hop on distinct
    /// non-tunnel interfaces that are connected; 'metricSpread' is the
    /// difference of their effective metrics (null if a metric is unknown);
    /// 'selectedIsTunnel' tells whether Windows routes an external address
    /// through a tunnel (routeSelection). With a full VPN tunnel two default
    /// routes are normal, so rules must look at the selection, not only at
    /// metrics (stage 1 finding). Requires 'routing'; uses fact 'adapters'.
    /// </summary>
    public sealed class RouteSummaryFacts : IFactProvider
    {
        public string Name => "routeSummary";

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var adapters = context.Get("adapters");
            if (!adapters.Available) fact.Limitations.Add("tunnel-detection-unavailable:" + adapters.UnavailableReason);

            // Interface index + family -> connected, from routing.interfaces.
            var connected = new Dictionary<string, bool>(StringComparer.Ordinal);
            foreach (var itf in JsonValue.GetList(routing, "interfaces"))
            {
                var key = JsonValue.Get(itf, "interfaceIndex") + "/" + JsonValue.AsString(JsonValue.Get(itf, "addressFamily"));
                connected[key] = JsonValue.AsString(JsonValue.Get(itf, "connectionState")) == "Connected";
            }

            var selection = new Dictionary<string, int?>(StringComparer.Ordinal);
            foreach (var s in JsonValue.GetList(routing, "routeSelection"))
            {
                var kind = JsonValue.AsString(JsonValue.Get(s, "kind"));
                if (kind == "externalIPv4") selection["IPv4"] = JsonValue.AsInt(JsonValue.Get(s, "interfaceIndex"));
                if (kind == "externalIPv6") selection["IPv6"] = JsonValue.AsInt(JsonValue.Get(s, "interfaceIndex"));
            }

            var routes = JsonValue.GetList(routing, "routes");
            foreach (var family in new[] { "IPv4", "IPv6" })
            {
                var prefix = family == "IPv4" ? "0.0.0.0/0" : "::/0";
                var defaults = new List<KeyValuePair<int, object>>();
                for (var i = 0; i < routes.Count; i++)
                {
                    var r = routes[i];
                    if (JsonValue.AsString(JsonValue.Get(r, "destinationPrefix")) != prefix) continue;
                    var index = JsonValue.AsInt(JsonValue.Get(r, "interfaceIndex"));
                    bool isConnected;
                    if (index != null && connected.TryGetValue(index + "/" + family, out isConnected) && !isConnected) continue;
                    defaults.Add(new KeyValuePair<int, object>(i, r));
                }

                var evidence = new List<string>();
                var gatewayInterfaces = new List<string>();
                var metrics = new List<decimal?>();
                var seen = new HashSet<int>();
                foreach (var pair in defaults)
                {
                    var r = pair.Value;
                    var nextHop = JsonValue.AsString(JsonValue.Get(r, "nextHop"));
                    if (nextHop == null || nextHop == "0.0.0.0" || nextHop == "::") continue;
                    var index = JsonValue.AsInt(JsonValue.Get(r, "interfaceIndex"));
                    if (index == null || !seen.Add(index.Value)) continue;
                    if (AdapterFacts.IsTunnel(adapters, index) == true) continue;
                    gatewayInterfaces.Add(JsonValue.AsString(JsonValue.Get(r, "interfaceAlias")));
                    metrics.Add(JsonValue.AsDecimal(JsonValue.Get(r, "effectiveMetric")));
                    evidence.Add("routing.routes[" + pair.Key + "]");
                }
                if (defaults.Count == 0) continue;

                decimal? spread = null;
                if (metrics.Count >= 2 && metrics.All(m => m != null)) spread = metrics.Max() - metrics.Min();
                int? selected;
                selection.TryGetValue(family, out selected);
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["family"] = family,
                    ["defaultRoutes"] = defaults.Count,
                    ["gateways"] = gatewayInterfaces.Count,
                    ["gatewayInterfaces"] = gatewayInterfaces.ToArray(),
                    ["metricSpread"] = spread,
                    ["selectedInterfaceIndex"] = selected,
                    ["selectedIsTunnel"] = AdapterFacts.IsTunnel(adapters, selected),
                }, evidence));
            }
            return fact;
        }
    }
}
