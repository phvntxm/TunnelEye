// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'missingFiles': entries that start a program whose file is gone
    /// (imageExists = false in 'services') - traces of removed software:
    /// - kind = service, driver: a service or driver of any start mode;
    /// - kind = autostart: an enabled Run key or Startup item;
    /// - kind = task: an action of a third-party scheduled task that is not
    ///   disabled.
    /// Paths under \WindowsApps\ are left out: packaged apps and app
    /// execution aliases are not readable, so the check says "missing" for
    /// files that exist (found on a real snapshot). clientId: the VPN client
    /// the service belongs to (vpn.clients), null if none - VPN traces are
    /// the 'vpn-leftovers' rule. Requires 'services'; 'vpn' is optional.
    /// </summary>
    public sealed class MissingFileFacts : IFactProvider
    {
        public string Name => "missingFiles";

        public FactSet Build(FactContext context)
        {
            string reason;
            var services = context.ModuleData("services", out reason);
            if (services == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);

            string vpnReason;
            var vpn = context.ModuleData("vpn", out vpnReason);
            if (vpn == null) fact.Limitations.Add("vpn-clients-unknown:" + vpnReason);
            var owners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var client in JsonValue.GetList(vpn, "clients"))
            {
                var id = JsonValue.AsString(JsonValue.Get(client, "id"));
                foreach (var section in new[] { "services", "drivers" })
                    foreach (var s in JsonValue.GetList(client, section))
                    {
                        var name = JsonValue.AsString(JsonValue.Get(s, "name"));
                        if (name != null && !owners.ContainsKey(name)) owners[name] = id;
                    }
            }

            foreach (var section in new[] { "services", "drivers" })
            {
                var list = JsonValue.GetList(services, section);
                for (var i = 0; i < list.Count; i++)
                {
                    var s = list[i];
                    if (!Missing(s)) continue;
                    var name = JsonValue.AsString(JsonValue.Get(s, "name"));
                    string owner;
                    owners.TryGetValue(name ?? "", out owner);
                    Add(fact, section == "services" ? "service" : "driver", name, s, JsonValue.AsString(JsonValue.Get(s, "state")), JsonValue.AsString(JsonValue.Get(s, "startMode")), owner, "services." + section + "[" + i + "]");
                }
            }

            var autostart = JsonValue.GetList(services, "autostart");
            for (var i = 0; i < autostart.Count; i++)
            {
                var a = autostart[i];
                if (!Missing(a) || JsonValue.AsBool(JsonValue.Get(a, "enabled")) == false) continue;
                Add(fact, "autostart", JsonValue.AsString(JsonValue.Get(a, "name")) + " (" + JsonValue.AsString(JsonValue.Get(a, "location")) + ")", a, null, null, null, "services.autostart[" + i + "]");
            }

            var tasks = JsonValue.GetList(JsonValue.Get(services, "scheduledTasks"), "thirdParty");
            for (var i = 0; i < tasks.Count; i++)
            {
                var t = tasks[i];
                var state = JsonValue.AsString(JsonValue.Get(t, "state"));
                if (state == "Disabled") continue;
                var actions = JsonValue.GetList(t, "actions");
                for (var j = 0; j < actions.Count; j++)
                {
                    if (!Missing(actions[j])) continue;
                    Add(fact, "task", JsonValue.AsString(JsonValue.Get(t, "taskPath")) + JsonValue.AsString(JsonValue.Get(t, "taskName")), actions[j], state, null, null,
                        "services.scheduledTasks.thirdParty[" + i + "].actions[" + j + "]");
                }
            }
            return fact;
        }

        private static bool Missing(object entry)
        {
            if (JsonValue.AsBool(JsonValue.Get(entry, "imageExists")) != false) return false;
            var path = JsonValue.AsString(JsonValue.Get(entry, "imagePath")) ?? "";
            return path.IndexOf(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) < 0;
        }

        private static void Add(FactSet fact, string kind, string name, object entry, string state, string startMode, string clientId, string evidence)
        {
            fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["kind"] = kind,
                ["name"] = name,
                ["imagePath"] = JsonValue.AsString(JsonValue.Get(entry, "imagePath")),
                ["state"] = state,
                ["startMode"] = startMode,
                ["clientId"] = clientId,
            }, new[] { evidence }));
        }
    }
}
