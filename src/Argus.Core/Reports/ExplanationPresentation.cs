// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.Linq;
using Argus.Core.Json;

namespace Argus.Core.Reports
{
    /// <summary>Shared text-only projection of the supplied, possibly masked model.</summary>
    public static class ExplanationPresentation
    {
        public static string[] Headers(string language) => new[] { "Status", "ExClaims", "ExConfiguration", "EvidenceSource" }
            .Select(k => ReportText.Get(k, language)).ToArray();

        public static IEnumerable<string[]> Rows(object explanation, string language)
        {
            var evidence = JsonValue.GetList(explanation, "evidence");
            foreach (var claim in JsonValue.GetList(explanation, "claims"))
            {
                var refs = JsonValue.GetList(claim, "evidenceRefs");
                var sources = evidence.Where(e => refs.Contains(JsonValue.Get(e, "id")))
                    .SelectMany(e => JsonValue.GetList(e, "sources")).OfType<string>().Distinct();
                yield return new[] {
                    ReportText.Get("ExKind_" + JsonValue.Get(claim, "kind"), language) + " · " +
                    ReportText.Get("ExAvailability_" + JsonValue.Get(claim, "availability"), language),
                    JsonValue.AsString(JsonValue.Get(claim, "text")), JsonValue.AsString(JsonValue.Get(claim, "scope")),
                    string.Join("\n", sources) };
            }
        }

        public static IEnumerable<string> Paths(object explanation, string language)
        {
            var path = JsonValue.Get(explanation, "path");
            var nodes = JsonValue.GetList(path, "nodes");
            foreach (var edge in JsonValue.GetList(path, "edges"))
            {
                var from = nodes.FirstOrDefault(n => Equals(JsonValue.Get(n, "id"), JsonValue.Get(edge, "from")));
                var to = nodes.FirstOrDefault(n => Equals(JsonValue.Get(n, "id"), JsonValue.Get(edge, "to")));
                yield return JsonValue.Get(from, "text") + " → " + JsonValue.Get(to, "text") + " · " +
                    ReportText.Get("ExPath_" + JsonValue.Get(edge, "kind"), language) + ": " + JsonValue.Get(edge, "text");
            }
        }
    }
}
