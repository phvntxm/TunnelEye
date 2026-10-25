// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'bridges': Windows Network Bridges (MAC Bridge miniport,
    /// routing.bridge.adapters) with their members - adapters with the
    /// ms_bridge binding. Virtual machine bridges (Hyper-V switch, VMware,
    /// VirtualBox) use their own drivers and are not here. Requires 'routing'.
    /// </summary>
    public sealed class BridgeFacts : IFactProvider
    {
        public string Name => "bridges";

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var bridge = JsonValue.Get(routing, "bridge");
            var members = JsonValue.GetList(bridge, "members");
            var adapters = JsonValue.GetList(bridge, "adapters");
            for (var i = 0; i < adapters.Count; i++)
            {
                var evidence = new List<string> { "routing.bridge.adapters[" + i + "]" };
                for (var j = 0; j < members.Count; j++) evidence.Add("routing.bridge.members[" + j + "]");
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["name"] = JsonValue.AsString(JsonValue.Get(adapters[i], "name")),
                    ["status"] = JsonValue.AsString(JsonValue.Get(adapters[i], "status")),
                    ["members"] = members.Count,
                    ["memberNames"] = members.Select(m => JsonValue.AsString(JsonValue.Get(m, "name"))).ToArray(),
                }, evidence));
            }
            return fact;
        }
    }

    /// <summary>
    /// Fact 'connectionSharing': Internet Connection Sharing (routing.ics).
    /// With administrator rights - the connections with sharing on
    /// (sharingType Public: the shared connection, Private: the one that
    /// receives it). Without them the list is not readable: while the
    /// SharedAccess service runs, the private side is found by the ICS scope
    /// address assigned to an interface (inferred = true), with a limitation.
    /// Requires 'routing'.
    /// </summary>
    public sealed class ConnectionSharingFacts : IFactProvider
    {
        public string Name => "connectionSharing";

        public FactSet Build(FactContext context)
        {
            string reason;
            var routing = context.ModuleData("routing", out reason);
            if (routing == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);

            var ics = JsonValue.Get(routing, "ics");
            var connections = JsonValue.AsList(JsonValue.Get(ics, "connections"));
            if (connections != null)
            {
                for (var i = 0; i < connections.Count; i++)
                {
                    var c = connections[i];
                    if (JsonValue.AsBool(JsonValue.Get(c, "sharingEnabled")) != true) continue;
                    fact.Items.Add(Item(JsonValue.AsString(JsonValue.Get(c, "name")), JsonValue.AsString(JsonValue.Get(c, "sharingType")), false, new[] { "routing.ics.connections[" + i + "]" }));
                }
                return fact;
            }

            // A stopped SharedAccess service shares nothing.
            var service = JsonValue.Get(ics, "service");
            if (JsonValue.AsString(JsonValue.Get(service, "status")) != "Running") return fact;
            fact.Limitations.Add("ics-connections-not-read");
            var scope = JsonValue.AsString(JsonValue.Get(service, "scopeAddress"));
            if (scope == null) return fact;
            var addresses = JsonValue.GetList(routing, "addresses");
            for (var i = 0; i < addresses.Count; i++)
            {
                if (!Addresses.Same(JsonValue.AsString(JsonValue.Get(addresses[i], "ipAddress")), scope)) continue;
                fact.Items.Add(Item(JsonValue.AsString(JsonValue.Get(addresses[i], "interfaceAlias")), "Private", true, new[] { "routing.ics.service", "routing.addresses[" + i + "]" }));
            }
            return fact;
        }

        private static FactItem Item(string name, string sharingType, bool inferred, IEnumerable<string> evidence)
        {
            return new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["name"] = name,
                ["sharingType"] = sharingType,
                ["inferred"] = inferred,
            }, evidence);
        }
    }
}
