// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Facts;
using Argus.Core.Json;
using Argus.Core.Rules;
using Argus.Core.Snapshots;

namespace Argus.Core.Engine
{
    public enum RuleStatus
    {
        Found,
        NotFound,
        /// <summary>A needed fact is unavailable: never "all is well" (D-014).</summary>
        NotChecked,
    }

    public sealed class Evidence
    {
        public Evidence(IDictionary<string, object> values, IReadOnlyList<string> sources)
        {
            Values = values;
            Sources = sources;
        }

        public IDictionary<string, object> Values { get; }
        public IReadOnlyList<string> Sources { get; }
    }

    public sealed class RuleResult
    {
        public RuleResult(Rule rule, RuleStatus status, string reason, IReadOnlyList<Evidence> evidence, IReadOnlyList<string> limitations)
        {
            Rule = rule;
            Status = status;
            Reason = reason;
            Evidence = evidence;
            Limitations = limitations;
        }

        public Rule Rule { get; }
        public RuleStatus Status { get; }
        /// <summary>Why the rule is not checked (for example "module-failed:routing").</summary>
        public string Reason { get; }
        public IReadOnlyList<Evidence> Evidence { get; }
        /// <summary>Parts of the facts that could not be checked although the rule ran.</summary>
        public IReadOnlyList<string> Limitations { get; }
    }

    public sealed class AnalysisResult
    {
        public const string Schema = "tunneleye.analysis/1";

        public AnalysisResult(string snapshotId, IReadOnlyList<RuleResult> results, IReadOnlyList<string> ruleErrors)
        {
            SnapshotId = snapshotId;
            Results = results;
            RuleErrors = ruleErrors;
        }

        public string SnapshotId { get; }
        public IReadOnlyList<RuleResult> Results { get; }
        public IReadOnlyList<string> RuleErrors { get; }
    }

    /// <summary>Evaluates rules over the facts of one snapshot.</summary>
    public sealed class RuleEngine
    {
        private readonly FactCatalog _catalog;

        public RuleEngine(FactCatalog catalog)
        {
            _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        }

        public AnalysisResult Evaluate(Snapshot snapshot, IEnumerable<Rule> rules, IEnumerable<string> ruleErrors = null)
        {
            var context = _catalog.CreateContext(snapshot);
            var results = new List<RuleResult>();
            foreach (var rule in rules) results.Add(Evaluate(context, rule, snapshot.CreatedAtUtc));
            return new AnalysisResult(snapshot.SnapshotId, results, (ruleErrors ?? new string[0]).ToList());
        }

        private static RuleResult Evaluate(FactContext context, Rule rule, DateTime nowUtc)
        {
            var limitations = new List<string>();
            foreach (var name in rule.Facts)
            {
                var fact = context.Get(name);
                if (!fact.Available) return new RuleResult(rule, RuleStatus.NotChecked, fact.UnavailableReason, new Evidence[0], new string[0]);
                limitations.AddRange(fact.Limitations);
            }
            var source = context.Get(rule.Condition.From);
            var evaluation = new EvaluationContext(rule.Thresholds, nowUtc);
            var matches = rule.Condition.Match(source, evaluation);
            var found = rule.Condition.IsMet(matches.Count, evaluation);
            var evidence = found ? matches.Select(m => new Evidence(m.Values, m.Evidence)).ToList() : new List<Evidence>();
            return new RuleResult(rule, found ? RuleStatus.Found : RuleStatus.NotFound, null, evidence, limitations.Distinct().ToList());
        }
    }

    /// <summary>JSON of an analysis (tunneleye.analysis/1): the rule results, not yet the report of stage 2.3.</summary>
    public static class AnalysisJson
    {
        public static string Write(AnalysisResult analysis)
        {
            var results = analysis.Results.Select(r => new Dictionary<string, object>
            {
                ["ruleId"] = r.Rule.Id,
                ["level"] = LevelName(r.Rule.Level),
                ["experimental"] = r.Rule.Experimental,
                ["status"] = StatusName(r.Status),
                ["reason"] = r.Reason,
                ["limitations"] = r.Limitations.ToArray(),
                ["evidence"] = r.Evidence.Select(e => new Dictionary<string, object> { ["values"] = e.Values, ["sources"] = e.Sources.ToArray() }).ToArray(),
            }).ToArray();
            return JsonValue.Serialize(new Dictionary<string, object>
            {
                ["schema"] = AnalysisResult.Schema,
                ["facts"] = FactCatalog.Version,
                ["snapshotId"] = analysis.SnapshotId,
                ["ruleErrors"] = analysis.RuleErrors.ToArray(),
                ["results"] = results,
            });
        }

        public static string LevelName(RuleLevel level)
        {
            switch (level)
            {
                case RuleLevel.Critical: return "critical";
                case RuleLevel.Important: return "important";
                case RuleLevel.Advice: return "advice";
                default: return "info";
            }
        }

        public static string StatusName(RuleStatus status)
        {
            switch (status)
            {
                case RuleStatus.Found: return "found";
                case RuleStatus.NotFound: return "notFound";
                default: return "notChecked";
            }
        }
    }
}
