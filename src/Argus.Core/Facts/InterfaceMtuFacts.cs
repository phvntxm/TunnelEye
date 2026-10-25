// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'interfaceMtu': IPv4 MTU of physical adapters that are up (not
    /// tunnels: a tunnel has a smaller MTU by design, and PPPoE is a PPP
    /// adapter). Fields:
    /// - nlMtu: MTU of the IP interface (routing.interfaces);
    /// - adapterMtu: MTU of the adapter (adapters);
    /// - gatewayMtu: path MTU to the default gateway found by 'connectivity'
    ///   (local echo with Don't Fragment), null if not measured;
    /// - registryMtu: MTU set by hand in Tcpip\Parameters\Interfaces
    ///   (tcp-stack); 0 is written by some VPN clients and is not a tweak.
    /// Requires 'routing' and fact 'adapters'.
    /// </summary>
    public sealed class InterfaceMtuFacts : IFactProvider
    {
        public string Name => "interfaceMtu";

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var adapters = context.Get("adapters");
            if (!adapters.Available) return FactSet.Unavailable(Name, adapters.UnavailableReason);
            var fact = FactSet.Create(Name);
            string ignored;
            var connectivity = context.ModuleData("connectivity", out ignored);
            var tcpStack = context.ModuleData("tcp-stack", out ignored);

            var interfaces = JsonValue.GetList(routing, "interfaces");
            var gateways = JsonValue.GetList(connectivity, "gateways");
            var registry = JsonValue.GetList(JsonValue.Get(tcpStack, "registry"), "interfaces");
            foreach (var adapter in adapters.Items)
            {
                if (!AdapterFacts.IsPhysicalUp(adapter)) continue;
                var index = JsonValue.AsInt(adapter.Values["interfaceIndex"]);
                var evidence = new List<string>(adapter.Evidence);

                int? nlMtu = null;
                for (var i = 0; i < interfaces.Count; i++)
                {
                    var itf = interfaces[i];
                    if (JsonValue.AsInt(JsonValue.Get(itf, "interfaceIndex")) != index || JsonValue.AsString(JsonValue.Get(itf, "addressFamily")) != "IPv4") continue;
                    if (JsonValue.AsString(JsonValue.Get(itf, "connectionState")) != "Connected") break;
                    nlMtu = JsonValue.AsInt(JsonValue.Get(itf, "nlMtu"));
                    evidence.Add("routing.interfaces[" + i + "]");
                    break;
                }
                if (nlMtu == null) continue;

                int? gatewayMtu = null;
                for (var i = 0; i < gateways.Count; i++)
                {
                    var g = gateways[i];
                    if (JsonValue.AsString(JsonValue.Get(g, "family")) != "IPv4" || JsonValue.AsInt(JsonValue.Get(g, "interfaceIndex")) != index) continue;
                    var mtu = JsonValue.Get(g, "mtu");
                    if (JsonValue.AsString(JsonValue.Get(mtu, "status")) != "ok") continue;
                    gatewayMtu = JsonValue.AsInt(JsonValue.Get(mtu, "mtu"));
                    evidence.Add("connectivity.gateways[" + i + "]");
                    break;
                }

                int? registryMtu = null;
                var guid = JsonValue.AsString(adapter.Values["interfaceGuid"]);
                for (var i = 0; i < registry.Count && guid != null; i++)
                {
                    var r = registry[i];
                    if (!string.Equals(JsonValue.AsString(JsonValue.Get(r, "interfaceGuid")), guid, StringComparison.OrdinalIgnoreCase) || JsonValue.AsString(JsonValue.Get(r, "addressFamily")) != "IPv4") continue;
                    foreach (var v in JsonValue.GetList(r, "values"))
                    {
                        if (!string.Equals(JsonValue.AsString(JsonValue.Get(v, "name")), "MTU", StringComparison.OrdinalIgnoreCase)) continue;
                        var value = JsonValue.AsInt(JsonValue.Get(v, "value"));
                        if (value == null || value == 0) continue;
                        registryMtu = value;
                        evidence.Add("tcp-stack.registry.interfaces[" + i + "]");
                    }
                }

                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["name"] = adapter.Values["name"],
                    ["interfaceIndex"] = index,
                    ["nlMtu"] = nlMtu,
                    ["adapterMtu"] = adapter.Values["mtu"],
                    ["gatewayMtu"] = gatewayMtu,
                    ["registryMtu"] = registryMtu,
                }, evidence));
            }
            return fact;
        }
    }
}
