// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Argus.Core.Json;

namespace Argus.Core.Reports
{
    /// <summary>Read-only presentation of the supplied report tree, including its masking.</summary>
    public sealed class EvidenceTable
    {
        private EvidenceTable(string address, object[] evidence)
        {
            Address = address;
            Evidence = evidence;
            IsHosts = evidence.All(e => JsonValue.GetList(e, "sources").Any(s =>
                (s as string)?.StartsWith("dns-proxy.hosts.entries[", StringComparison.Ordinal) == true));
        }

        public string Address { get; }
        public object[] Evidence { get; }
        public bool IsHosts { get; }
        public string Title(string language) => (Address.Length == 0 ? ReportText.Get("EvidenceOther", language) : Address) + " · " + Evidence.Length;
        public string[] Headers(string language) => (IsHosts ? new[] { "EvidenceDomain", "EvidenceAddress", "EvidenceSource" } :
            new[] { "EvidenceField", "EvidenceValue", "EvidenceSource" }).Select(k => ReportText.Get(k, language)).ToArray();

        public IEnumerable<string[]> Rows(string language)
        {
            foreach (var item in Evidence)
            {
                var values = JsonValue.AsObject(JsonValue.Get(item, "values"));
                var source = Display(JsonValue.Get(item, "sources"), language);
                if (IsHosts)
                    yield return new[] { Display(JsonValue.Get(values, "name"), language), Display(JsonValue.Get(values, "address"), language), source };
                else if (values == null || values.Count == 0)
                    yield return new[] { ReportText.Get("EvidenceValue", language), Display(values, language), source };
                else
                    foreach (var value in values)
                    {
                        var key = "EvidenceField_" + value.Key;
                        var label = ReportText.Get(key, language);
                        if (label == key) label = ReportText.Get("EvidenceField", language) + " (" + value.Key + ")";
                        yield return new[] { label, Display(value.Value, language), source };
                    }
            }
        }

        private static string Display(object value, string language)
        {
            if (value == null) return ReportText.Get("EvidenceUnknown", language);
            if (value is bool) return ReportText.Get((bool)value ? "EvidenceYes" : "EvidenceNo", language);
            var list = JsonValue.AsList(value);
            if (list != null) return list.Count == 0 ? ReportText.Get("EvidenceEmpty", language) : string.Join("\n", list.Select(v => Display(v, language)));
            var obj = JsonValue.AsObject(value);
            if (obj != null) return string.Join("\n", obj.Select(p => p.Key + ": " + Display(p.Value, language)));
            return Convert.ToString(value, CultureInfo.GetCultureInfo(language));
        }

        public static IEnumerable<EvidenceTable> Groups(object check) => JsonValue.GetList(check, "evidence")
            .GroupBy(e => JsonValue.AsString(JsonValue.Get(JsonValue.Get(e, "values"), "address")) ?? "", StringComparer.Ordinal)
            .Select(g => new EvidenceTable(g.Key, g.ToArray()));
    }
}
