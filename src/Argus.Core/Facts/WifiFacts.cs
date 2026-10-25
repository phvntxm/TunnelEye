// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'wifiLinks': one item per connected Wi-Fi interface (module 'wifi').
    /// - bandGHz: from netsh, or from the channel on Windows 10 (1-14 -> 2.4);
    /// - linkGeneration / apGeneration / cardGeneration: Wi-Fi generation of
    ///   the link (interfaces[].radioType), of the access point
    ///   (neighbors.bss[connected].radioType) and the best the card supports
    ///   (drivers[].radioTypesSupported): 802.11b 1, a 2, g 3, n 4, ac 5,
    ///   ax 6, be 7. Card ax and point ac - the router limits; point ax and
    ///   link ac - the client side (HANDOFF, material for stage 2);
    /// - overlappingNetworks: on 2.4 GHz only, access points of other networks
    ///   within 4 channels (they share the air); null without a scan;
    /// - channelUtilizationPercent: load of the channel the point reports.
    /// Requires 'wifi' (skipped without a Wi-Fi adapter).
    /// </summary>
    public sealed class WifiFacts : IFactProvider
    {
        public string Name => "wifiLinks";

        public FactSet Build(FactContext context)
        {
            string reason;
            var wifi = context.ModuleData("wifi", out reason);
            if (wifi == null) return FactSet.Unavailable(Name, reason);
            var fact = FactSet.Create(Name);
            var drivers = JsonValue.GetList(wifi, "drivers");
            var neighbors = JsonValue.Get(wifi, "neighbors");
            var bss = JsonValue.GetList(neighbors, "bss");
            if (neighbors == null) fact.Limitations.Add("wifi-scan-not-read");

            var interfaces = JsonValue.GetList(wifi, "interfaces");
            for (var i = 0; i < interfaces.Count; i++)
            {
                var itf = interfaces[i];
                if (JsonValue.AsBool(JsonValue.Get(itf, "connected")) != true) continue;
                var name = JsonValue.AsString(JsonValue.Get(itf, "name"));
                var channel = JsonValue.AsInt(JsonValue.Get(itf, "channel"));
                var band = Band(JsonValue.AsString(JsonValue.Get(itf, "bandGHz")), channel);
                var evidence = new List<string> { "wifi.interfaces[" + i + "]" };
                var link = Generation(JsonValue.AsString(JsonValue.Get(itf, "radioType")));

                int? card = null;
                for (var k = 0; k < drivers.Count; k++)
                {
                    var d = drivers[k];
                    var driverInterface = JsonValue.AsString(JsonValue.Get(d, "interfaceName"));
                    if (drivers.Count > 1 && !string.Equals(driverInterface, name, StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var radio in JsonValue.GetList(d, "radioTypesSupported"))
                    {
                        var g = Generation(JsonValue.AsString(radio));
                        if (g != null && (card == null || g > card)) card = g;
                    }
                    evidence.Add("wifi.drivers[" + k + "]");
                    break;
                }

                int? ap = null, utilization = null, overlapping = null;
                if (neighbors != null && band == "2.4" && channel != null) overlapping = 0;
                for (var m = 0; m < bss.Count; m++)
                {
                    var b = bss[m];
                    var scanInterface = JsonValue.AsString(JsonValue.Get(b, "interfaceName"));
                    if (scanInterface != null && !string.Equals(scanInterface, name, StringComparison.OrdinalIgnoreCase)) continue;
                    var bChannel = JsonValue.AsInt(JsonValue.Get(b, "channel"));
                    if (JsonValue.AsBool(JsonValue.Get(b, "connected")) == true)
                    {
                        if (ap != null) continue;
                        ap = Generation(JsonValue.AsString(JsonValue.Get(b, "radioType")));
                        utilization = JsonValue.AsInt(JsonValue.Get(b, "channelUtilizationPercent"));
                        evidence.Add("wifi.neighbors.bss[" + m + "]");
                        continue;
                    }
                    if (overlapping == null || bChannel == null) continue;
                    if (Band(JsonValue.AsString(JsonValue.Get(b, "bandGHz")), bChannel) == "2.4" && Math.Abs(bChannel.Value - channel.Value) <= 4) overlapping++;
                }

                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["name"] = name,
                    ["signalPercent"] = JsonValue.AsInt(JsonValue.Get(itf, "signalPercent")),
                    ["bandGHz"] = band,
                    ["channel"] = channel,
                    ["radioType"] = JsonValue.AsString(JsonValue.Get(itf, "radioType")),
                    ["linkGeneration"] = link,
                    ["apGeneration"] = ap,
                    ["cardGeneration"] = card,
                    // Conditions cannot compare two fields, so the comparisons are facts.
                    ["accessPointBelowCard"] = ap == null || card == null ? (bool?)null : ap < card,
                    ["linkBelowAccessPoint"] = link == null || ap == null || card == null ? (bool?)null : link < ap && link < card,
                    ["overlappingNetworks"] = overlapping,
                    ["channelUtilizationPercent"] = utilization,
                }, evidence));
            }
            return fact;
        }

        internal static string Band(string bandGHz, int? channel)
        {
            if (!string.IsNullOrEmpty(bandGHz)) return bandGHz;
            if (channel == null) return null;
            return channel.Value <= 14 ? "2.4" : "5";
        }

        internal static int? Generation(string radioType)
        {
            switch ((radioType ?? "").Trim().ToLowerInvariant())
            {
                case "802.11b": return 1;
                case "802.11a": return 2;
                case "802.11g": return 3;
                case "802.11n": return 4;
                case "802.11ac": return 5;
                case "802.11ax": return 6;
                case "802.11be": return 7;
                default: return null;
            }
        }
    }
}
