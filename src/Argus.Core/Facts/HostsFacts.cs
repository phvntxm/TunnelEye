// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'hostsEntries': one item per name in the hosts file
    /// (dns-proxy.hosts.entries), with the address and its class:
    /// unspecified/loopback - the name is blocked; private - a machine in the
    /// local network; public - the name is pinned to an internet address,
    /// which goes stale. Which names are sensitive (banks, payments, updates,
    /// antivirus) is a list in the rule, not here (D-007). Requires 'dns-proxy'.
    /// </summary>
    public sealed class HostsFacts : IFactProvider
    {
        public string Name => "hostsEntries";

        public FactSet Build(FactContext context)
        {
            string reason;
            var dns = context.ModuleData("dns-proxy", out reason);
            if (dns == null) return FactSet.Unavailable(Name, reason);
            var hosts = JsonValue.Get(dns, "hosts");
            if (hosts == null) return FactSet.Unavailable(Name, "section-missing:dns-proxy.hosts");
            var fact = FactSet.Create(Name);
            var entries = JsonValue.GetList(hosts, "entries");
            for (var i = 0; i < entries.Count; i++)
            {
                var address = JsonValue.AsString(JsonValue.Get(entries[i], "address"));
                foreach (var name in JsonValue.GetList(entries[i], "names"))
                {
                    fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["address"] = address,
                        ["name"] = JsonValue.AsString(name),
                        ["addressClass"] = Addresses.Class(address),
                    }, new[] { "dns-proxy.hosts.entries[" + i + "]" }));
                }
            }
            return fact;
        }
    }
}
