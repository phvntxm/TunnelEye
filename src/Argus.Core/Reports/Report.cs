// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Resources;
using Argus.Core.Engine;
using Argus.Core.Json;
using Argus.Core.Rules;
using Argus.Core.Snapshots;

namespace Argus.Core.Reports
{
    public static class ReportText
    {
        private static readonly ResourceManager Resources = new ResourceManager("Argus.Core.Reports.Strings", typeof(ReportText).Assembly);
        public static string Get(string key, string language) => Resources.GetString(key, CultureInfo.GetCultureInfo(language)) ?? key;
    }

    /// <summary>Detached report tree shared by CLI, HTML and the future WPF view.</summary>
    public sealed class Report
    {
        public const string Schema = "tunneleye.report/1";
        internal Report(IDictionary<string, object> root) { Root = root; }
        public IDictionary<string, object> Root { get; }
        public string Json() => JsonValue.Serialize(Root);
        public Report Masked(PrivacyMasker masker) => new Report(JsonValue.AsObject(masker.Transform(Root)));

        public static Report Build(Snapshot snapshot, AnalysisResult analysis, string language = "ru")
        {
            if (language != "ru" && language != "en") throw new ArgumentException("Unsupported language.", nameof(language));
            var results = analysis.Results.OrderBy(r => r.Rule.Level).ThenBy(r => r.Rule.Id, StringComparer.Ordinal).ToList();
            var found = results.Where(r => r.Status == RuleStatus.Found).ToList();
            var missingCritical = results.Where(r => !r.Rule.Experimental && r.Rule.Level == RuleLevel.Critical &&
                (r.Status == RuleStatus.NotChecked || r.Limitations.Count > 0)).ToList();
            var score = found.Any(r => !r.Rule.Experimental && r.Rule.Level == RuleLevel.Critical) ? "red" :
                found.Any(r => !r.Rule.Experimental && r.Rule.Level == RuleLevel.Important) ? "yellow" :
                missingCritical.Count > 0 || analysis.RuleErrors.Count > 0 || analysis.EvaluationErrors.Count > 0 || results.Count == 0 ? "gray" : "green";
            var counts = Enum.GetValues(typeof(RuleLevel)).Cast<RuleLevel>().ToDictionary(l => AnalysisJson.LevelName(l), l => (object)found.Count(r => r.Rule.Level == l));
            var checks = results.Select(r => (object)new Dictionary<string, object>
            {
                ["id"] = r.Rule.Id, ["level"] = AnalysisJson.LevelName(r.Rule.Level), ["experimental"] = r.Rule.Experimental,
                ["status"] = r.Status == RuleStatus.NotChecked && IsNotApplicable(snapshot, r.Reason) ? "notApplicable" : AnalysisJson.StatusName(r.Status),
                ["title"] = r.Rule.Text["title"].For(language), ["why"] = r.Rule.Text["why"].For(language), ["fix"] = r.Rule.Text["fix"].For(language),
                ["details"] = r.Rule.Text.ContainsKey("details") ? r.Rule.Text["details"].For(language) : null,
                ["reason"] = r.Reason, ["hint"] = Hint(r.Reason, language), ["limitations"] = r.Limitations.ToArray(),
                ["evidenceCount"] = r.Evidence.Count,
                ["evidence"] = r.Evidence.Select(e => (object)new Dictionary<string, object> { ["values"] = e.Values, ["sources"] = e.Sources.ToArray() }).ToArray(),
            }).ToArray();
            var sections = new Dictionary<string, object>();
            // Collector schemas already exclude passwords, packet bodies and browsing history.
            // Keep technical data collapsed; never execute or render it as markup.
            foreach (var module in snapshot.Modules)
                sections[module.Name] = JsonValue.Get(JsonValue.Get(JsonValue.Get(snapshot.Root, "modules"), module.Name), "data");
            var tree = new Dictionary<string, object>
            {
                ["schema"] = Schema, ["snapshotId"] = snapshot.SnapshotId, ["createdAt"] = snapshot.CreatedAtUtc.ToString("o", CultureInfo.InvariantCulture),
                ["version"] = typeof(Report).Assembly.GetName().Version.ToString(), ["language"] = language, ["masked"] = false,
                ["summary"] = new Dictionary<string, object> { ["score"] = score, ["counts"] = counts,
                    ["incompleteCritical"] = missingCritical.Select(r => r.Rule.Id).ToArray(),
                    ["recommendations"] = found.OrderBy(r => r.Rule.Experimental).ThenBy(r => r.Rule.Level).Take(3).Select(r => r.Rule.Id).ToArray() },
                ["checks"] = checks, ["sections"] = sections, ["charts"] = ReportCharts.Build(snapshot),
                ["modules"] = snapshot.Modules.Select(m => (object)new Dictionary<string, object> { ["name"] = m.Name, ["status"] = m.Status,
                    ["errors"] = m.Status == "skipped" ? new object[0] : m.Errors.Select(e => (object)new Dictionary<string, object> { ["source"] = e.Source, ["kind"] = e.Kind, ["message"] = e.Message }).ToArray() }).ToArray(),
                ["ruleErrors"] = analysis.RuleErrors.ToArray(), ["evaluationErrors"] = analysis.EvaluationErrors.ToArray(),
            };
            return new Report(JsonValue.AsObject(JsonValue.Parse(JsonValue.Serialize(tree))));
        }

        private static bool IsNotApplicable(Snapshot snapshot, string reason)
        {
            const string prefix = "module-skipped:";
            if (reason == null || !reason.StartsWith(prefix, StringComparison.Ordinal)) return false;
            var module = snapshot.Module(reason.Substring(prefix.Length));
            return module != null && module.Status == "skipped" && module.Errors.All(e => e.Kind == "NotSupported");
        }

        private static string Hint(string reason, string language)
        {
            if (reason == null) return null;
            return ReportText.Get(reason.Contains("external-not-allowed") ? "ConsentHint" :
                reason.Contains("wfp-not-collected") || reason.Contains("AccessDenied") ? "AdminHint" : "CheckHint", language);
        }
    }
}
