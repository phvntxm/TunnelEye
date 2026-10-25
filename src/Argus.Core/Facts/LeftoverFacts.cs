// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'leftovers': traces of VPN software that is no longer in use, from
    /// the 'vpn' module. Kinds:
    /// - tunnelDriverWithoutAdapter: a TAP-Windows driver is installed, but no
    ///   adapter uses it. Not Wintun: it creates adapters only while a tunnel
    ///   runs and ships with the apps that use it, so a Wintun driver without
    ///   an adapter is normal (found on a real snapshot);
    /// - tapAdapterWithoutClient: a TAP-Windows adapter that no installed VPN
    ///   client claims (OpenVPN uses TAP, so its presence keeps TAP adapters);
    /// - adapterNotPresent: an adapter of a VPN client that Windows keeps as
    ///   'Not Present' (removed device, driver still registered).
    /// Stage 2.2 adds service files that no longer exist and WFP providers
    /// without a client.
    /// </summary>
    public sealed class LeftoverFacts : IFactProvider
    {
        private static readonly HashSet<string> TunnelDrivers = new HashSet<string>(StringComparer.Ordinal) { "tap-windows" };
        // Specific clients that use TAP-Windows adapters.
        private static readonly HashSet<string> TapUsers = new HashSet<string>(StringComparer.Ordinal) { "openvpn" };

        public string Name => "leftovers";

        public FactSet Build(FactContext context)
        {
            string reason;
            var vpn = context.ModuleData("vpn", out reason);
            if (vpn == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var clients = JsonValue.GetList(vpn, "clients");

            var tapUserInstalled = false;
            foreach (var c in clients)
            {
                if (!TapUsers.Contains(JsonValue.AsString(JsonValue.Get(c, "id")) ?? "")) continue;
                if (JsonValue.GetList(c, "software").Count > 0 || JsonValue.GetList(c, "services").Count > 0) tapUserInstalled = true;
            }

            for (var i = 0; i < clients.Count; i++)
            {
                var c = clients[i];
                var id = JsonValue.AsString(JsonValue.Get(c, "id"));
                var name = JsonValue.AsString(JsonValue.Get(c, "name"));
                var generic = JsonValue.AsBool(JsonValue.Get(c, "generic")) == true;
                var adapters = JsonValue.GetList(c, "adapters");
                var drivers = JsonValue.GetList(c, "drivers");
                var path = "vpn.clients[" + i + "]";

                if (generic && TunnelDrivers.Contains(id ?? "") && drivers.Count > 0 && adapters.Count == 0)
                {
                    Add(fact, "tunnelDriverWithoutAdapter", id, name, JsonValue.AsString(JsonValue.Get(drivers[0], "name")), null, path + ".drivers[0]");
                }
                for (var j = 0; j < adapters.Count; j++)
                {
                    var a = adapters[j];
                    var status = JsonValue.AsString(JsonValue.Get(a, "status"));
                    var description = JsonValue.AsString(JsonValue.Get(a, "interfaceDescription"));
                    if (string.Equals(status, "Not Present", StringComparison.OrdinalIgnoreCase))
                        Add(fact, "adapterNotPresent", id, name, description, status, path + ".adapters[" + j + "]");
                    else if (generic && id == "tap-windows" && !tapUserInstalled)
                        Add(fact, "tapAdapterWithoutClient", id, name, description, status, path + ".adapters[" + j + "]");
                }
            }
            return fact;
        }

        private static void Add(FactSet fact, string kind, string clientId, string clientName, string detail, string status, string evidence)
        {
            fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["kind"] = kind,
                ["clientId"] = clientId,
                ["clientName"] = clientName,
                ["detail"] = detail,
                ["status"] = status,
            }, new[] { evidence }));
        }
    }
}
