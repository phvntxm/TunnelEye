// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Argus.Core.Engine;
using Argus.Core.Json;
using Argus.Core.Snapshots;
using Xunit;
using Xunit.Abstractions;

namespace Argus.Core.Tests
{
    /// <summary>
    /// TZ regression: a rule works if it finds its problem on its snapshot and
    /// stays silent on the clean one. Snapshots are synthetic (D-014).
    /// </summary>
    public class RegressionTests
    {
        private readonly ITestOutputHelper _output;

        public RegressionTests(ITestOutputHelper output) { _output = output; }

        private static RuleResult Result(string snapshot, string ruleId)
        {
            return TestData.Analyze(TestData.LoadSnapshot(snapshot)).Results.Single(r => r.Rule.Id == ruleId);
        }

        /// <summary>Problem snapshot -> the one rule it must trigger.</summary>
        private static readonly Dictionary<string, string> Problems = new Dictionary<string, string>
        {
            ["two-gateways"] = "two-gateways",
            ["dead-proxy"] = "dead-proxy",
            ["vpn-leftovers"] = "vpn-leftovers",
            ["orphaned-wfp-provider"] = "vpn-leftovers",
            ["vpn-service-missing"] = "vpn-leftovers",
            ["vpn-conflict"] = "vpn-conflict",
            ["ndis-filter-leftover"] = "ndis-filter-leftover",
            ["dns-leak"] = "dns-leak",
            ["ipv6-bypass"] = "ipv6-bypass",
            ["wfp-conflict"] = "wfp-conflict",
            ["hosts-sensitive"] = "hosts-sensitive",
            ["hosts-sensitive-blocked"] = "hosts-sensitive-blocked",
            ["elevated-as-other-user"] = "elevated-as-other-user",
            ["dead-proxy-other-user"] = "elevated-as-other-user",
            ["hosts-pinned"] = "hosts-pinned",
            ["network-bridge"] = "network-bridge",
            ["connection-sharing"] = "connection-sharing",
            ["routing-loop"] = "routing-loop",
            ["outdated-driver"] = "outdated-driver",
            ["adapter-power-saving"] = "adapter-power-saving",
            ["mtu-low"] = "mtu-low",
            ["missing-files"] = "missing-files",
            ["wifi-weak-signal"] = "wifi-weak-signal",
            ["wifi-crowded-channel"] = "wifi-crowded-channel",
            ["wifi-router-limits"] = "wifi-router-limits",
            ["wifi-link-below-capability"] = "wifi-link-below-capability",
            ["open-ports"] = "open-ports",
            ["dns-spoofing"] = "dns-spoofing",
            ["not-elevated"] = "not-elevated",
            ["external-not-run"] = "external-not-run",
        };

        /// <summary>Snapshots on which nothing may be found.</summary>
        private static readonly string[] Silent = { "clean", "clean-wifi", "full-tunnel", "routing-failed" };

        public static IEnumerable<object[]> ProblemCases() => Problems.Select(p => new object[] { p.Key, p.Value });

        /// <summary>
        /// On a clean base every rule is really checked - not "not checked":
        /// the bases carry all 13 modules, external tests and WFP, so silence
        /// there means the rule looked and found nothing.
        /// </summary>
        [Theory]
        [InlineData("clean")]
        [InlineData("clean-wifi")]
        public void Nothing_is_found_on_a_clean_snapshot(string snapshot)
        {
            var analysis = TestData.Analyze(TestData.LoadSnapshot(snapshot));
            Assert.Empty(analysis.RuleErrors);
            Assert.Empty(analysis.EvaluationErrors);
            foreach (var r in analysis.Results) Assert.True(r.Status == RuleStatus.NotFound, r.Rule.Id + " is " + r.Status + " (" + r.Reason + ") on " + snapshot);
        }

        [Theory]
        [MemberData(nameof(ProblemCases))]
        public void Each_rule_finds_its_problem(string snapshot, string ruleId)
        {
            var r = Result(snapshot, ruleId);
            Assert.Equal(RuleStatus.Found, r.Status);
            Assert.NotEmpty(r.Evidence);
            Assert.All(r.Evidence, e => Assert.NotEmpty(e.Sources));
        }

        [Theory]
        [MemberData(nameof(ProblemCases))]
        public void A_problem_snapshot_triggers_only_its_rule(string snapshot, string ruleId)
        {
            var analysis = TestData.Analyze(TestData.LoadSnapshot(snapshot));
            Assert.Empty(analysis.EvaluationErrors);
            var found = analysis.Results.Where(r => r.Status == RuleStatus.Found).Select(r => r.Rule.Id).ToList();
            Assert.Equal(new[] { ruleId }, found);
        }

        [Fact]
        public void Every_rule_has_a_problem_snapshot_and_every_snapshot_a_role()
        {
            var rules = TestData.LoadRules();
            Assert.Empty(rules.Errors);
            Assert.Empty(rules.Rules.Select(r => r.Id).Except(Problems.Values));
            Assert.Empty(TestData.SnapshotNames().Except(Problems.Keys).Except(Silent));
        }

        [Theory]
        [InlineData("full-tunnel")]
        [InlineData("routing-failed")]
        public void Nothing_is_found_on_a_silent_snapshot(string snapshot)
        {
            Assert.Empty(TestData.Analyze(TestData.LoadSnapshot(snapshot)).Results.Where(r => r.Status == RuleStatus.Found).Select(r => r.Rule.Id));
        }

        [Fact]
        public void A_wintun_driver_without_an_adapter_is_not_a_leftover()
        {
            var json = File.ReadAllText(Path.Combine(TestData.SnapshotsDir, "clean.json"), Encoding.UTF8);
            json = json.Replace("\"clients\": []", "\"clients\": [ { \"id\": \"wintun\", \"name\": \"Wintun driver\", \"kind\": \"driver\", \"generic\": true, \"software\": [], \"services\": [], \"drivers\": [ { \"name\": \"wintun\", \"state\": \"Stopped\" } ], \"adapters\": [], \"processes\": [] } ]");
            Assert.Contains("wintun", json);
            var r = TestData.Analyze(Snapshot.Parse(json)).Results.Single(x => x.Rule.Id == "vpn-leftovers");
            Assert.Equal(RuleStatus.NotFound, r.Status);
        }

        [Fact]
        public void Two_default_routes_under_a_full_tunnel_are_normal()
        {
            Assert.Equal(RuleStatus.NotFound, Result("full-tunnel", "two-gateways").Status);
        }

        [Fact]
        public void Two_gateways_evidence_points_to_the_routes()
        {
            var r = Result("two-gateways", "two-gateways");
            var sources = r.Evidence.SelectMany(e => e.Sources).ToList();
            Assert.Contains("routing.routes[0]", sources);
            Assert.Contains("routing.routes[1]", sources);
            Assert.Equal(5m, JsonValue.AsDecimal(r.Evidence[0].Values["metricSpread"]));
        }

        [Fact]
        public void A_failed_module_makes_its_rules_not_checked()
        {
            var r = Result("routing-failed", "two-gateways");
            Assert.Equal(RuleStatus.NotChecked, r.Status);
            Assert.Equal("module-failed:routing", r.Reason);
            Assert.Equal(RuleStatus.NotFound, Result("routing-failed", "dead-proxy").Status);
        }

        [Fact]
        public void A_missing_module_makes_its_rules_not_checked()
        {
            var json = File.ReadAllText(Path.Combine(TestData.SnapshotsDir, "clean.json"), Encoding.UTF8);
            var tree = JsonValue.AsObject(JsonValue.Parse(json));
            JsonValue.AsObject(tree["modules"]).Remove("vpn");
            var r = TestData.Analyze(Snapshot.Parse(JsonValue.Serialize(tree))).Results.Single(x => x.Rule.Id == "vpn-leftovers");
            Assert.Equal(RuleStatus.NotChecked, r.Status);
            Assert.Equal("module-missing:vpn", r.Reason);
        }

        [Fact]
        public void User_proxy_is_not_checked_under_another_administrator()
        {
            var r = Result("dead-proxy-other-user", "dead-proxy");
            Assert.Equal(RuleStatus.NotFound, r.Status);
            Assert.Contains("elevated-as-other-user:user-proxy-not-checked", r.Limitations);
        }

        [Fact]
        public void Analysis_json_has_schema_and_statuses()
        {
            var json = AnalysisJson.Write(TestData.Analyze(TestData.LoadSnapshot("dead-proxy")));
            var tree = JsonValue.Parse(json);
            Assert.Equal("tunneleye.analysis/1", JsonValue.Get(tree, "schema"));
            Assert.Equal("facts/1", JsonValue.Get(tree, "facts"));
            var statuses = JsonValue.GetList(tree, "results").Select(r => (string)JsonValue.Get(r, "status")).ToList();
            Assert.Contains("found", statuses);
            Assert.All(statuses, s => Assert.Contains(s, new[] { "found", "notFound", "notChecked" }));
        }

        /// <summary>
        /// Optional regress on real snapshots kept locally (.local/regress,
        /// never in git): each &lt;name&gt;.json may have &lt;name&gt;.expected.json with
        /// {"absent": [rule ids], "present": [rule ids]}. Without the folder the
        /// test passes doing nothing.
        /// </summary>
        [Fact]
        public void Local_real_snapshots_match_their_expectations()
        {
            if (!Directory.Exists(TestData.LocalRegressDir)) { _output.WriteLine("No .local/regress: skipped."); return; }
            foreach (var path in Directory.GetFiles(TestData.LocalRegressDir, "*.json").Where(p => !p.EndsWith(".expected.json")))
            {
                var analysis = TestData.Analyze(Snapshot.Load(path));
                var found = new HashSet<string>(analysis.Results.Where(r => r.Status == RuleStatus.Found).Select(r => r.Rule.Id));
                _output.WriteLine(Path.GetFileName(path) + ": " + string.Join(", ", analysis.Results.Select(r => r.Rule.Id + "=" + AnalysisJson.StatusName(r.Status))));
                var expectedPath = Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + ".expected.json");
                if (!File.Exists(expectedPath)) continue;
                var expected = JsonValue.Parse(File.ReadAllText(expectedPath, Encoding.UTF8));
                foreach (var id in JsonValue.GetList(expected, "absent")) Assert.False(found.Contains((string)id), Path.GetFileName(path) + ": " + id + " must not be found");
                foreach (var id in JsonValue.GetList(expected, "present")) Assert.True(found.Contains((string)id), Path.GetFileName(path) + ": " + id + " must be found");
            }
        }
    }
}
