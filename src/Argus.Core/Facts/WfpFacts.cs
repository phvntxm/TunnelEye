// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'wfpLayers': WFP layers where third-party callouts decide on
    /// traffic (firewall.wfp, administrator rights only). One item per layer
    /// with at least one third-party owner of a filter with a terminating
    /// callout action (FWP_ACTION_CALLOUT_TERMINATING or _UNKNOWN; inspection
    /// callouts only look). The owner is the filter's provider, else the
    /// callout's provider, else the callout itself (WinDivert has no
    /// provider). Microsoft owners - FWPM_PROVIDER_* constants, resource names
    /// (@...dll) and names with Microsoft/Windows - are left out: Windows and
    /// Defender callouts coexist with others by design. Several third-party
    /// owners on one layer may contradict each other - an unconfirmed sign
    /// (experimental rule, reply to plan 006, item 5). Requires 'firewall'.
    /// </summary>
    public sealed class WfpFacts : IFactProvider
    {
        private static readonly Regex MicrosoftName = new Regex(@"^@|\bmicrosoft\b|\bwindows\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private const int MaxEvidence = 10;

        public string Name => "wfpLayers";

        public FactSet Build(FactContext context)
        {
            string reason;
            var firewall = context.ModuleData("firewall", out reason);
            if (firewall == null) return FactSet.Unavailable(Name, reason);
            var wfp = JsonValue.Get(firewall, "wfp");
            if (wfp == null) return FactSet.Unavailable(Name, "wfp-not-collected");
            var fact = FactSet.Create(Name);

            var providers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in JsonValue.GetList(wfp, "providers"))
            {
                var key = JsonValue.AsString(JsonValue.Get(p, "providerKey"));
                if (key != null) providers[key] = JsonValue.AsString(JsonValue.Get(p, "name"));
            }
            var callouts = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in JsonValue.GetList(wfp, "callouts"))
            {
                var key = JsonValue.AsString(JsonValue.Get(c, "calloutKey"));
                if (key != null) callouts[key] = c;
            }

            // Layer -> owner key -> (owner name, filter paths).
            var layers = new Dictionary<string, Dictionary<string, Tuple<string, List<string>>>>(StringComparer.OrdinalIgnoreCase);
            var layerOrder = new List<string>();
            var filters = JsonValue.GetList(wfp, "filters");
            for (var i = 0; i < filters.Count; i++)
            {
                var f = filters[i];
                var action = JsonValue.AsString(JsonValue.Get(f, "action"));
                if (action != "FWP_ACTION_CALLOUT_TERMINATING" && action != "FWP_ACTION_CALLOUT_UNKNOWN") continue;
                var calloutKey = JsonValue.AsString(JsonValue.Get(f, "calloutKey"));
                object callout = null;
                if (calloutKey != null) callouts.TryGetValue(calloutKey, out callout);
                var providerKey = JsonValue.AsString(JsonValue.Get(f, "providerKey")) ?? JsonValue.AsString(JsonValue.Get(callout, "providerKey"));
                string ownerKey, ownerName;
                if (providerKey != null)
                {
                    ownerKey = providerKey;
                    string name;
                    providers.TryGetValue(providerKey, out name);
                    ownerName = name ?? providerKey;
                    if (IsMicrosoftProvider(providerKey, name)) continue;
                }
                else
                {
                    ownerKey = "callout:" + (calloutKey ?? "?");
                    ownerName = JsonValue.AsString(JsonValue.Get(callout, "name")) ?? calloutKey;
                    if (ownerName != null && MicrosoftName.IsMatch(ownerName)) continue;
                }
                var layer = JsonValue.AsString(JsonValue.Get(f, "layerKey")) ?? "?";
                Dictionary<string, Tuple<string, List<string>>> owners;
                if (!layers.TryGetValue(layer, out owners)) { layers[layer] = owners = new Dictionary<string, Tuple<string, List<string>>>(StringComparer.OrdinalIgnoreCase); layerOrder.Add(layer); }
                Tuple<string, List<string>> owner;
                if (!owners.TryGetValue(ownerKey, out owner)) owners[ownerKey] = owner = Tuple.Create(ownerName, new List<string>());
                owner.Item2.Add("firewall.wfp.filters[" + i + "]");
            }

            foreach (var layer in layerOrder)
            {
                var owners = layers[layer];
                // A few filters of each owner, so every owner is in the evidence.
                var evidence = owners.Values.SelectMany(o => o.Item2.Take(Math.Max(1, MaxEvidence / owners.Count))).ToList();
                fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["layerKey"] = layer,
                    ["thirdPartyOwners"] = owners.Count,
                    ["owners"] = owners.Values.Select(o => o.Item1).ToArray(),
                    ["filters"] = owners.Values.Sum(o => o.Item2.Count),
                }, evidence));
            }
            return fact;
        }

        /// <summary>Whether a WFP provider is Windows' own: an FWPM_PROVIDER_* constant or a Microsoft/resource name.</summary>
        internal static bool IsMicrosoftProvider(string providerKey, string name)
        {
            return (providerKey != null && providerKey.StartsWith("FWPM_PROVIDER_", StringComparison.OrdinalIgnoreCase)) || (name != null && MicrosoftName.IsMatch(name));
        }
    }
}
