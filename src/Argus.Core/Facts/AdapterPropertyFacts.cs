// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Fact 'adapterProperties': advanced properties of physical adapters
    /// that are up (adapters.adapters[].advancedProperties), one item per
    /// property: keyword (*EEE, EnableGreenEthernet, ...), value - the raw
    /// registry value (the display value is localized), and the form factor
    /// of the PC from 'hardware': isDesktop is true for Desktop and
    /// Workstation, false for Mobile and Slate, null otherwise. Which keywords
    /// mean power saving is a list in the rule. Requires 'adapters'.
    /// </summary>
    public sealed class AdapterPropertyFacts : IFactProvider
    {
        public string Name => "adapterProperties";

        public FactSet Build(FactContext context)
        {
            string reason;
            var data = context.ModuleData("adapters", out reason);
            if (data == null) return FactSet.Unavailable(Name, reason);
            var adapters = context.Get("adapters");
            if (!adapters.Available) return FactSet.Unavailable(Name, adapters.UnavailableReason);
            var fact = FactSet.Create(Name);

            string hardwareReason;
            var hardware = context.ModuleData("hardware", out hardwareReason);
            var formFactor = JsonValue.AsString(JsonValue.Get(JsonValue.Get(hardware, "system"), "pcSystemType"));
            bool? isDesktop = null;
            if (formFactor == "Desktop" || formFactor == "Workstation") isDesktop = true;
            else if (formFactor == "Mobile" || formFactor == "Slate") isDesktop = false;
            if (isDesktop == null) fact.Limitations.Add("form-factor-unknown:" + (hardware == null ? hardwareReason : formFactor ?? "null"));

            var raw = JsonValue.GetList(data, "adapters");
            for (var i = 0; i < raw.Count; i++)
            {
                var adapter = AdapterFacts.Find(adapters, JsonValue.AsInt(JsonValue.Get(raw[i], "interfaceIndex")));
                if (!AdapterFacts.IsPhysicalUp(adapter)) continue;
                var path = "adapters.adapters[" + i + "]";
                var properties = JsonValue.GetList(raw[i], "advancedProperties");
                for (var j = 0; j < properties.Count; j++)
                {
                    var p = properties[j];
                    var values = JsonValue.GetList(p, "registryValue");
                    fact.Items.Add(new FactItem(new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["adapter"] = adapter.Values["name"],
                        ["interfaceIndex"] = adapter.Values["interfaceIndex"],
                        ["keyword"] = JsonValue.AsString(JsonValue.Get(p, "keyword")),
                        ["value"] = values.Count > 0 ? Convert.ToString(values[0], System.Globalization.CultureInfo.InvariantCulture) : null,
                        ["displayValue"] = JsonValue.AsString(JsonValue.Get(p, "displayValue")),
                        ["formFactor"] = formFactor,
                        ["isDesktop"] = isDesktop,
                    }, new[] { path + ".advancedProperties[" + j + "]" }));
                }
            }
            return fact;
        }
    }
}
