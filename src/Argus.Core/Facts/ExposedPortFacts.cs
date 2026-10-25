// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Argus.Core.Json;
using Argus.Core.Rules;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'exposedPorts': TCP ports listening on all interfaces (0.0.0.0 or
    /// ::, connections.tcpListeners), one item per port and process, with:
    /// - publicNetwork: a connected network is in the Public profile
    ///   (system.networkProfiles);
    /// - inboundAllowed: the Windows firewall lets connections to the port in
    ///   on the Public profile - the profile is off or allows inbound by
    ///   default, or an enabled inbound allow rule for Public (or Any) matches
    ///   the port (protocol TCP or Any; the port, a range or Any; the program
    ///   Any or the listener's process) and no block rule does. A block rule
    ///   wins, as in Windows. Null if a rule could match but a filter of it is
    ///   unread (without administrator rights the address filters are not
    ///   readable, and a broad rule may be limited to 127.0.0.1) or a service
    ///   rule cannot be tied to the process, and with a third-party firewall
    ///   in charge; then the limitation firewall-filters-not-read.
    /// A listening port alone is not a problem: inbound connections on Public
    /// are blocked by default (HANDOFF, material for stage 2).
    /// Requires 'connections'; 'system' and 'firewall' give the rest.
    /// </summary>
    public sealed class ExposedPortFacts : IFactProvider
    {
        public string Name => "exposedPorts";

        public FactSet Build(FactContext context)
        {
            string reason;
            var connections = context.ModuleData("connections", out reason);
            if (connections == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);

            string systemReason;
            var system = context.ModuleData("system", out systemReason);
            bool? publicNetwork = null;
            var profileEvidence = new List<string>();
            if (system == null || JsonValue.Get(system, "networkProfiles") == null) fact.Limitations.Add("network-profile-unknown:" + (systemReason ?? "section-missing:system.networkProfiles"));
            else
            {
                publicNetwork = false;
                var profiles = JsonValue.GetList(system, "networkProfiles");
                for (var i = 0; i < profiles.Count; i++)
                {
                    if (JsonValue.AsString(JsonValue.Get(profiles[i], "category")) != "Public") continue;
                    publicNetwork = true;
                    profileEvidence.Add("system.networkProfiles[" + i + "]");
                }
            }

            string firewallReason;
            var firewall = context.ModuleData("firewall", out firewallReason);
            if (firewall == null) fact.Limitations.Add("firewall-unknown:" + firewallReason);
            var thirdParty = JsonValue.GetList(firewall, "products").Any(p => JsonValue.AsBool(JsonValue.Get(p, "enabled")) == true);
            if (thirdParty) fact.Limitations.Add("third-party-firewall");

            // The Public profile itself: off or allowing inbound by default lets everything in.
            Truth profileVerdict = Truth.Unknown;
            foreach (var p in JsonValue.GetList(firewall, "profiles"))
            {
                if (JsonValue.AsString(JsonValue.Get(p, "name")) != "Public") continue;
                if (JsonValue.AsBool(JsonValue.Get(p, "enabled")) == false || JsonValue.AsString(JsonValue.Get(p, "defaultInboundAction")) == "Allow") profileVerdict = Truth.True;
                else if (JsonValue.AsString(JsonValue.Get(p, "allowInboundRules")) == "False") profileVerdict = Truth.False;
                else profileVerdict = Truth.Unknown;
            }
            var rules = JsonValue.GetList(firewall, "rules");

            var listeners = JsonValue.GetList(connections, "tcpListeners");
            var groups = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
            var order = new List<string>();
            for (var i = 0; i < listeners.Count; i++)
            {
                if (JsonValue.AsString(JsonValue.Get(listeners[i], "localClass")) != "unspecified") continue;
                var key = JsonValue.Get(listeners[i], "localPort") + "/" + JsonValue.AsString(JsonValue.Get(listeners[i], "process"));
                List<int> list;
                if (!groups.TryGetValue(key, out list)) { groups[key] = list = new List<int>(); order.Add(key); }
                list.Add(i);
            }

            foreach (var key in order)
            {
                var first = listeners[groups[key][0]];
                var port = JsonValue.AsInt(JsonValue.Get(first, "localPort"));
                var process = JsonValue.AsString(JsonValue.Get(first, "process"));
                var evidence = groups[key].Select(i => "connections.tcpListeners[" + i + "]").ToList();
                evidence.AddRange(profileEvidence);

                bool? allowed = null;
                var allowing = 0;
                if (firewall != null && !thirdParty && port != null)
                {
                    var allow = Truth.False;
                    var block = false;
                    for (var r = 0; r < rules.Count; r++)
                    {
                        var rule = rules[r];
                        if (JsonValue.AsBool(JsonValue.Get(rule, "enabled")) != true || JsonValue.AsString(JsonValue.Get(rule, "direction")) != "Inbound") continue;
                        if (JsonValue.AsString(JsonValue.Get(rule, "primaryStatus")) == "Inactive") continue;
                        var profiles = JsonValue.GetList(rule, "profiles").Select(JsonValue.AsString).ToList();
                        if (!profiles.Contains("Any") && !profiles.Contains("Public")) continue;
                        var match = Matches(rule, port.Value, process);
                        if (match == Truth.False) continue;
                        if (JsonValue.AsString(JsonValue.Get(rule, "action")) == "Block") { if (match == Truth.True) block = true; continue; }
                        if (match == Truth.True)
                        {
                            allow = Truth.True;
                            if (allowing++ < 5) evidence.Add("firewall.rules[" + r + "]");
                        }
                        else if (allow == Truth.False) allow = Truth.Unknown;
                    }
                    if (block) allowed = false;
                    else if (profileVerdict == Truth.True) allowed = true;
                    else if (profileVerdict == Truth.False) allowed = false;
                    else allowed = allow == Truth.True ? true : allow == Truth.False ? false : (bool?)null;
                    if (allowed == null && !fact.Limitations.Contains("firewall-filters-not-read")) fact.Limitations.Add("firewall-filters-not-read");
                }

                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["port"] = port,
                    ["process"] = process,
                    ["addresses"] = groups[key].Select(i => JsonValue.AsString(JsonValue.Get(listeners[i], "localAddress"))).ToArray(),
                    ["publicNetwork"] = publicNetwork,
                    ["inboundAllowed"] = allowed,
                    ["allowingRules"] = allowing,
                }, evidence));
            }
            return fact;
        }

        /// <summary>
        /// Whether a firewall rule applies to TCP on this port for this
        /// process, in three-valued logic: any part False gives False, else an
        /// unread filter (null - without administrator rights the address and
        /// part of the port filters are not readable) gives Unknown. A rule of
        /// a package (AppContainer) applies only to that app; a rule only for
        /// loopback remote addresses does not open the port to the network.
        /// </summary>
        internal static Truth Matches(object rule, int port, string process)
        {
            var parts = new List<Truth>();

            var protocol = JsonValue.AsString(JsonValue.Get(rule, "protocol"));
            parts.Add(protocol == null ? Truth.Unknown : protocol == "TCP" || protocol == "Any" || protocol == "6" ? Truth.True : Truth.False);

            var portsNode = JsonValue.AsList(JsonValue.Get(rule, "localPorts"));
            var explicitPort = false;
            if (portsNode == null) parts.Add(Truth.Unknown);
            else
            {
                var ports = portsNode.Select(JsonValue.AsString).Where(p => p != null).ToList();
                explicitPort = ports.Any(p => PortIn(p, port));
                parts.Add(explicitPort || ports.Contains("Any") ? Truth.True : Truth.False);
            }

            var program = JsonValue.AsString(JsonValue.Get(rule, "program"));
            if (program == null) parts.Add(Truth.Unknown);
            else if (program == "Any") parts.Add(Truth.True);
            else if (string.Equals(program, "System", StringComparison.OrdinalIgnoreCase)) parts.Add(string.Equals(process, "System", StringComparison.OrdinalIgnoreCase) ? Truth.True : Truth.False);
            else
            {
                var file = program.Substring(program.LastIndexOfAny(new[] { '\\', '/' }) + 1);
                if (file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) file = file.Substring(0, file.Length - 4);
                parts.Add(string.Equals(file, process, StringComparison.OrdinalIgnoreCase) ? Truth.True : Truth.False);
            }

            if (!string.IsNullOrEmpty(JsonValue.AsString(JsonValue.Get(rule, "package")))) parts.Add(Truth.False);

            // A service rule: the hosting svchost cannot be tied to the service
            // (no PIDs of services in the snapshot) unless the port is explicit.
            var service = JsonValue.AsString(JsonValue.Get(rule, "service"));
            if (service != null && service != "Any" && service != "*" && !explicitPort) parts.Add(Truth.Unknown);

            var local = JsonValue.AsList(JsonValue.Get(rule, "localAddresses"));
            var remote = JsonValue.AsList(JsonValue.Get(rule, "remoteAddresses"));
            if (local == null || remote == null) parts.Add(Truth.Unknown);
            else if (remote.Count > 0 && remote.All(a => Addresses.Class(JsonValue.AsString(a)) == "loopback")) parts.Add(Truth.False);

            if (parts.Contains(Truth.False)) return Truth.False;
            return parts.Contains(Truth.Unknown) ? Truth.Unknown : Truth.True;
        }

        /// <summary>"80", "1000-2000" contain the port; keywords (RPC, IPHTTPS, ...) do not.</summary>
        internal static bool PortIn(string spec, int port)
        {
            int a, b;
            var dash = spec.IndexOf('-');
            if (dash < 0) return int.TryParse(spec, NumberStyles.None, CultureInfo.InvariantCulture, out a) && a == port;
            return int.TryParse(spec.Substring(0, dash), NumberStyles.None, CultureInfo.InvariantCulture, out a)
                && int.TryParse(spec.Substring(dash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out b)
                && port >= a && port <= b;
        }
    }
}
