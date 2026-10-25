// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'tunnelCoverage': one item - what goes through a tunnel.
    /// - ipv4ViaTunnel / ipv6ViaTunnel: Windows routes an external address of
    ///   the family through a tunnel (routing.routeSelection; a full tunnel);
    /// - ipv6Reachable: there is a route to an external IPv6 address at all;
    /// - ipv6ExternalReached: an external IPv6 echo of 'connectivity' was
    ///   answered through a non-tunnel interface - the route is not only in
    ///   the table, traffic really passes by the tunnel (a VPN client may
    ///   block such traffic with WFP filters, so the route alone is not
    ///   proof). Null without external tests or IPv6 targets.
    /// Requires 'routing'; uses fact 'adapters' and 'connectivity'.
    /// </summary>
    public sealed class TunnelCoverageFacts : IFactProvider
    {
        public string Name => "tunnelCoverage";

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var adapters = context.Get("adapters");
            if (!adapters.Available) return FactSet.Unavailable(Name, adapters.UnavailableReason);
            var fact = FactSet.Create(Name);
            fact.Limitations.AddRange(adapters.Limitations);
            var evidence = new List<string>();

            int path4, path6;
            bool? reachable4, reachable6;
            var index4 = TunnelFacts.Selection(routing, "externalIPv4", out path4, out reachable4);
            var index6 = TunnelFacts.Selection(routing, "externalIPv6", out path6, out reachable6);
            if (path4 >= 0) evidence.Add("routing.routeSelection[" + path4 + "]");
            if (path6 >= 0) evidence.Add("routing.routeSelection[" + path6 + "]");
            var via4 = reachable4 == true ? AdapterFacts.IsTunnel(adapters, index4) : reachable4 == false ? false : (bool?)null;
            var via6 = reachable6 == true ? AdapterFacts.IsTunnel(adapters, index6) : reachable6 == false ? false : (bool?)null;

            // Confirmation by traffic: an answered IPv6 echo through a non-tunnel interface.
            bool? reached6 = null;
            string connectivityReason;
            var connectivity = context.ModuleData("connectivity", out connectivityReason);
            var external = JsonValue.Get(connectivity, "external");
            var notTested = connectivity == null ? connectivityReason : external == null ? "externalNotAllowed" : "no-ipv6-targets";
            var pings = JsonValue.GetList(external, "ping");
            for (var i = 0; i < pings.Count; i++)
            {
                var p = pings[i];
                if ((JsonValue.AsString(JsonValue.Get(p, "target")) ?? "").IndexOf(':') < 0) continue;
                if (reached6 == null) reached6 = false;
                if (JsonValue.AsString(JsonValue.Get(JsonValue.Get(p, "result"), "status")) != "Success") continue;
                if (AdapterFacts.IsTunnel(adapters, JsonValue.AsInt(JsonValue.Get(p, "viaInterfaceIndex"))) != false) continue;
                reached6 = true;
                evidence.Add("connectivity.external.ping[" + i + "]");
            }
            if (via4 == true && reachable6 == true && via6 == false && reached6 == null) fact.Limitations.Add("ipv6-not-tested:" + notTested);

            fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ipv4ViaTunnel"] = via4,
                ["ipv4InterfaceIndex"] = index4,
                ["ipv6Reachable"] = reachable6,
                ["ipv6ViaTunnel"] = via6,
                ["ipv6InterfaceIndex"] = index6,
                ["ipv6ExternalReached"] = reached6,
            }, evidence));
            return fact;
        }
    }
}
