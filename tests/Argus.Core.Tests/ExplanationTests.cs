// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Json;
using Argus.Core.Reports;
using Argus.Core.Snapshots;
using Xunit;

namespace Argus.Core.Tests
{
    public class ExplanationTests
    {
        private static IDictionary<string, object> Data(IDictionary<string, object> tree, string module) =>
            JsonValue.AsObject(JsonValue.Get(JsonValue.Get(tree["modules"], module), "data"));
        private static Snapshot Edit(string name, Action<IDictionary<string, object>> edit)
        { var tree = TestData.LoadTree(name); edit(tree); return Snapshot.Parse(JsonValue.Serialize(tree)); }
        private static Report ReportFor(Snapshot s, string language = "en") => Report.Build(s, TestData.Analyze(s), language);
        private static object Vpn(Report r) => JsonValue.GetList(r.Root, "explanations").Single(e => Equals(JsonValue.Get(e, "id"), "vpn-configuration"));
        private static object Proxy(Report r) => JsonValue.GetList(r.Root, "explanations").First(e => Equals(JsonValue.Get(e, "id"), "proxy-1"));
        private static RuleResult Result(Snapshot s, string id) => TestData.Analyze(s).Results.Single(r => r.Rule.Id == id);
        private static void Routes(IDictionary<string, object> tree, string family, string a, string b)
        {
            Data(tree, "routing")["routes"] = new[] { Row(family, a, 9), Row(family, b, 10) };
            Data(tree, "routing")["interfaces"] = new[] {
                ReportExplanations.Node("interfaceIndex", 9, "addressFamily", family, "connectionState", "Connected"),
                ReportExplanations.Node("interfaceIndex", 10, "addressFamily", family, "connectionState", "Connected") };
        }
        private static object Row(string family, string prefix, int index) => ReportExplanations.Node(
            "addressFamily", family, "destinationPrefix", prefix, "interfaceIndex", index);

        [Theory]
        [InlineData("IPv4", "0.0.0.0/0", "0.0.0.0/1", true)]
        [InlineData("IPv4", "0.0.0.0/1", "128.0.0.0/1", false)]
        [InlineData("IPv4", "0.0.0.0/1", "0.0.0.0/1", true)]
        [InlineData("IPv4", "10.0.0.0/8", "10.0.0.0/8", false)]
        [InlineData("IPv6", "::/0", "8000::/1", true)]
        [InlineData("IPv6", "::/1", "8000::/1", false)]
        [InlineData("IPv6", "::/1", "::/1", true)]
        public void Overlap_requires_intersecting_broad_prefixes_of_one_family(string family, string a, string b, bool expected)
        {
            var s = Edit("vpn-conflict", t => Routes(t, family, a, b));
            Assert.Equal(expected ? RuleStatus.Found : RuleStatus.NotFound, Result(s, "vpn-conflict").Status);
            var fact = FactCatalog.CreateDefault().CreateContext(s).Get("tunnel-route-overlaps");
            if (expected)
            {
                var item = Assert.Single(fact.Items);
                Assert.Equal(family, item.Values["family"]);
                Assert.DoesNotContain("0.0.0.0/0", JsonValue.AsList(item.Values["overlapPrefixes"]));
                Assert.Contains(item.Evidence, x => x.StartsWith("vpn.clients[", StringComparison.Ordinal));
            }
        }

        [Fact]
        public void Different_families_and_two_adapters_of_one_client_do_not_prove_overlap()
        {
            var s = Edit("vpn-conflict", t => {
                Routes(t, "IPv4", "0.0.0.0/0", "0.0.0.0/0");
                JsonValue.AsObject(JsonValue.GetList(Data(t, "routing"), "routes")[1])["addressFamily"] = "IPv6";
                JsonValue.AsObject(JsonValue.GetList(Data(t, "routing"), "routes")[1])["destinationPrefix"] = "::/0";
                JsonValue.AsObject(JsonValue.GetList(Data(t, "routing"), "interfaces")[1])["addressFamily"] = "IPv6";
            });
            Assert.Equal(RuleStatus.NotFound, Result(s, "vpn-conflict").Status);
            s = Edit("vpn-conflict", t => {
                var clients = JsonValue.GetList(Data(t, "vpn"), "clients");
                JsonValue.AsObject(clients[0])["adapters"] = new[] { ReportExplanations.Node("interfaceIndex", 9), ReportExplanations.Node("interfaceIndex", 10) };
                Data(t, "vpn")["clients"] = new[] { clients[0] };
            });
            Assert.Equal(RuleStatus.NotFound, Result(s, "vpn-conflict").Status);
        }

        [Theory]
        [InlineData("generic")]
        [InlineData("metadata-missing")]
        [InlineData("driver")]
        [InlineData("shared-core")]
        [InlineData("ambiguous")]
        [InlineData("inventory-error")]
        public void Unknown_or_generic_participant_never_becomes_a_second_proven_client(string mode)
        {
            var s = Edit("vpn-conflict", t => {
                var clients = JsonValue.GetList(Data(t, "vpn"), "clients");
                var client = JsonValue.AsObject(clients[1]);
                if (mode == "generic") client["generic"] = true;
                if (mode == "metadata-missing") client.Remove("generic");
                if (mode == "driver") client["kind"] = "driver";
                if (mode == "shared-core") client["id"] = "proxy-core";
                if (mode == "ambiguous") Data(t, "vpn")["clients"] = clients.Concat(new[] { ReportExplanations.Node("id", "third-client", "kind", "vpn", "generic", false,
                    "adapters", new[] { ReportExplanations.Node("interfaceIndex", 10) }) }).ToArray();
                if (mode == "inventory-error")
                {
                    Data(t, "vpn")["clients"] = new[] { clients[0] };
                    var module = JsonValue.AsObject(JsonValue.Get(t["modules"], "vpn"));
                    module["status"] = "partial";
                    module["errors"] = new[] { ReportExplanations.Node("source", "Get-NetAdapter", "kind", "AccessDenied", "message", "synthetic") };
                }
            });
            Assert.NotEqual(RuleStatus.Found, Result(s, "vpn-conflict").Status);
            var explanation = Vpn(ReportFor(s));
            Assert.Equal("insufficientData", JsonValue.Get(explanation, "assessment"));
            Assert.Contains(JsonValue.GetList(explanation, "claims"), c => Equals(JsonValue.Get(c, "availability"), "known"));
            Assert.DoesNotContain("The complete data contain no overlap", JsonValue.Serialize(explanation));
        }

        [Theory]
        [InlineData(null)]
        [InlineData(0)]
        [InlineData(500)]
        public void Metrics_do_not_turn_overlap_into_proven_failure(int? metric)
        {
            var s = Edit("vpn-conflict", t => {
                foreach (var row in JsonValue.GetList(Data(t, "routing"), "routes")) JsonValue.AsObject(row)["effectiveMetric"] = metric;
            });
            var report = ReportFor(s);
            Assert.Equal("yellow", JsonValue.Get(report.Root["summary"], "score"));
            Assert.Equal("possibleCause", JsonValue.Get(Vpn(report), "assessment"));
            Assert.Contains(JsonValue.GetList(Vpn(report), "claims"), c => Equals(JsonValue.Get(c, "kind"), "hypothesis") && Equals(JsonValue.Get(c, "availability"), "unknown"));
        }

        [Fact]
        public void Another_critical_still_wins_and_incomplete_vpn_does_not_control_gray()
        {
            var s = Edit("vpn-conflict", t => Data(t, "dns-proxy")["proxy"] = Data(TestData.LoadTree("dead-proxy"), "dns-proxy")["proxy"]);
            Assert.Equal("red", JsonValue.Get(ReportFor(s).Root["summary"], "score"));
            var incomplete = ReportFor(TestData.LoadSnapshot("routing-failed"));
            Assert.Equal("green", JsonValue.Get(incomplete.Root["summary"], "score"));
            Assert.Equal("insufficientData", JsonValue.Get(Vpn(incomplete), "assessment"));
            Assert.Contains("VPN check is incomplete", HtmlReport.Write(incomplete));
            Assert.DoesNotContain("vpn-conflict", JsonValue.GetList(incomplete.Root["summary"], "incompleteCritical"));
        }

        [Fact]
        public void Known_routes_survive_unknown_dns_and_do_not_promise_a_working_vpn()
        {
            var s = Edit("vpn-conflict", t => {
                var clients = JsonValue.GetList(Data(t, "vpn"), "clients");
                Data(t, "vpn")["clients"] = new[] { clients[0] };
                var routing = Data(t, "routing");
                routing["routes"] = JsonValue.GetList(routing, "routes").Where(r => JsonValue.AsInt(JsonValue.Get(r, "interfaceIndex")) != 10).ToArray();
                Data(t, "adapters")["adapters"] = JsonValue.GetList(Data(t, "adapters"), "adapters").Where(a => JsonValue.AsInt(JsonValue.Get(a, "interfaceIndex")) != 10).ToArray();
                Data(t, "dns-proxy").Remove("dnsServers");
            });
            var card = Vpn(ReportFor(s));
            Assert.Equal("expectedBehavior", JsonValue.Get(card, "assessment"));
            var claims = JsonValue.GetList(card, "claims");
            Assert.Contains(claims, c => Equals(JsonValue.Get(c, "availability"), "unknown") && ((string)JsonValue.Get(c, "text")).Contains("DNS"));
            Assert.Contains(claims, c => Equals(JsonValue.Get(c, "availability"), "known") && ((string)JsonValue.Get(c, "text")).Contains("Windows selected"));
            Assert.Contains("not been verified", (string)JsonValue.Get(card, "primaryLimitation"));
        }

        [Theory]
        [InlineData("refused", "refused", "confirmedConfigurationProblem")]
        [InlineData("timeout", "within the test period", "confirmedConfigurationProblem")]
        [InlineData("open", "protocol operation", "insufficientData")]
        [InlineData("error", "encountered an error", "insufficientData")]
        public void Tcp_results_are_distinct_and_open_does_not_prove_protocol_health(string status, string text, string assessment)
        {
            var s = Edit("dead-proxy", t => {
                JsonValue.AsObject(JsonValue.GetList(Data(t, "connectivity"), "proxies")[0])["status"] = status;
                // Keep a complete but empty listener table: an earlier successful
                // TCP test must not become a failure due to a later absent row.
            });
            var card = Proxy(ReportFor(s));
            Assert.Equal(assessment, JsonValue.Get(card, "assessment"));
            Assert.Contains(text, JsonValue.Serialize(card));
            if (status == "open") Assert.NotEqual(RuleStatus.Found, Result(s, "dead-proxy").Status);
        }

        [Theory]
        [InlineData("missing-table")]
        [InlineData("failed-module")]
        [InlineData("tcp-error")]
        [InlineData("malformed-listener")]
        public void Missing_listener_is_not_negative_evidence_without_a_complete_section(string mode)
        {
            var s = Edit("dead-proxy", t => {
                JsonValue.AsObject(JsonValue.GetList(Data(t, "connectivity"), "proxies")[0])["tested"] = false;
                if (mode == "missing-table") Data(t, "connections").Remove("tcpListeners");
                if (mode == "malformed-listener") Data(t, "connections")["tcpListeners"] = new[] { ReportExplanations.Node("localPort", 8118) };
                var module = JsonValue.AsObject(JsonValue.Get(t["modules"], "connections"));
                if (mode == "failed-module") { module["status"] = "failed"; module["data"] = null; }
                if (mode == "tcp-error") { module["status"] = "partial"; module["errors"] = new[] { ReportExplanations.Node("source", "Get-NetTCPConnection", "kind", "AccessDenied") }; }
            });
            Assert.NotEqual(RuleStatus.Found, Result(s, "dead-proxy").Status);
            var card = Proxy(ReportFor(s));
            Assert.Equal("insufficientData", JsonValue.Get(card, "assessment"));
            Assert.DoesNotContain("No matching listener for", JsonValue.Serialize(card));
        }

        [Fact]
        public void Unrelated_ics_error_does_not_hide_complete_routes_but_malformed_rows_prevent_negative_conclusions()
        {
            var s = Edit("vpn-expected", t => {
                var module = JsonValue.AsObject(JsonValue.Get(t["modules"], "routing"));
                module["status"] = "partial";
                module["errors"] = new[] { ReportExplanations.Node("source", "HNetCfg.HNetShare", "kind", "AccessDenied") };
            });
            Assert.Equal("expectedBehavior", JsonValue.Get(Vpn(ReportFor(s)), "assessment"));
            s = Edit("vpn-expected", t => JsonValue.AsObject(JsonValue.GetList(Data(t, "routing"), "routes")[0])["destinationPrefix"] = "malformed");
            Assert.Equal("insufficientData", JsonValue.Get(Vpn(ReportFor(s)), "assessment"));
        }

        [Theory]
        [InlineData("pac")]
        [InlineData("wpad")]
        [InlineData("missing-mode")]
        [InlineData("inconsistent-server")]
        public void Ambiguous_proxy_scope_keeps_the_setting_and_measurement_without_claiming_effectiveness(string mode)
        {
            var s = Edit("dead-proxy", t => {
                var u = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(Data(t, "dns-proxy"), "proxy"), "user"));
                var connection = JsonValue.AsObject(u["connectionSettings"]);
                if (mode == "pac") connection["autoConfigEnabled"] = true;
                if (mode == "wpad") connection["autoDetect"] = true;
                if (mode == "missing-mode") u.Remove("connectionSettings");
                if (mode == "inconsistent-server") connection["proxyServer"] = "127.0.0.1:9999";
            });
            Assert.NotEqual(RuleStatus.Found, Result(s, "dead-proxy").Status);
            var card = Proxy(ReportFor(s));
            Assert.Equal("insufficientData", JsonValue.Get(card, "assessment"));
            Assert.Contains("refused during", JsonValue.Serialize(card));
            Assert.Contains("scope is unknown", (string)JsonValue.Get(card, "primaryLimitation"));
        }

        [Fact]
        public void Negative_listener_evidence_names_the_section_and_preserves_temporal_limits()
        {
            var s = Edit("dead-proxy", t => JsonValue.AsObject(JsonValue.GetList(Data(t, "connectivity"), "proxies")[0])["tested"] = false);
            var card = Proxy(ReportFor(s));
            Assert.Equal("confirmedConfigurationProblem", JsonValue.Get(card, "assessment"));
            Assert.Contains(JsonValue.GetList(card, "evidence"), e => Equals(JsonValue.Get(e, "kind"), "section") &&
                JsonValue.GetList(e, "sources").Contains("connections.tcpListeners"));
            Assert.Contains("collected sequentially", JsonValue.Serialize(card));
            Assert.Contains("owning application is unknown", JsonValue.Serialize(card));
            Assert.DoesNotContain("refused during", JsonValue.Serialize(card));
        }

        [Theory]
        [InlineData("known")]
        [InlineData("possibleCause")]
        [InlineData("configuration")]
        [InlineData("configured")]
        [InlineData("observed")]
        [InlineData("node-1")]
        public void Personal_values_matching_protocol_words_do_not_corrupt_enums_but_text_and_scope_are_masked(string value)
        {
            var s = Edit("vpn-conflict", t => {
                Data(t, "wifi")["interfaces"] = new[] { ReportExplanations.Node("ssid", value) };
                Data(t, "vpn")["builtIn"] = ReportExplanations.Node("profiles", new[] { ReportExplanations.Node("name", value) });
            });
            var report = ReportFor(s);
            var card = JsonValue.AsObject(Vpn(report));
            var claim = JsonValue.AsObject(JsonValue.GetList(card, "claims")[0]);
            claim["text"] = value; claim["scope"] = value;
            var path = JsonValue.Get(card, "path");
            var pathNode = JsonValue.AsObject(JsonValue.GetList(path, "nodes")[0]); pathNode["text"] = value;
            JsonValue.AsObject(JsonValue.GetList(path, "edges")[0])["text"] = value;
            var masked = report.Masked(new PrivacyMasker(s));
            var maskedCard = Vpn(masked);
            Assert.Equal("possibleCause", JsonValue.Get(maskedCard, "assessment"));
            Assert.Equal("finding", JsonValue.Get(maskedCard, "placement"));
            var mc = JsonValue.GetList(maskedCard, "claims")[0];
            Assert.Equal("derived", JsonValue.Get(mc, "kind")); Assert.Equal("known", JsonValue.Get(mc, "availability"));
            Assert.NotEqual(value, JsonValue.Get(mc, "text")); Assert.NotEqual(value, JsonValue.Get(mc, "scope"));
            Assert.NotEqual(value, JsonValue.Get(JsonValue.GetList(JsonValue.Get(maskedCard, "path"), "nodes")[0], "text"));
            Assert.Equal("locallySelected", JsonValue.Get(JsonValue.GetList(JsonValue.Get(maskedCard, "path"), "edges")[0], "kind"));
            Assert.NotEqual(value, JsonValue.Get(JsonValue.GetList(JsonValue.Get(maskedCard, "path"), "edges")[0], "text"));
            var nodeIds = JsonValue.GetList(JsonValue.Get(maskedCard, "path"), "nodes").Select(n => JsonValue.Get(n, "id")).ToArray();
            Assert.All(JsonValue.GetList(JsonValue.Get(maskedCard, "path"), "edges"), e => {
                Assert.Contains(JsonValue.Get(e, "from"), nodeIds); Assert.Contains(JsonValue.Get(e, "to"), nodeIds); });
        }

        [Theory]
        [InlineData("vpn-expected", "expectedBehavior")]
        [InlineData("dead-proxy", "confirmedConfigurationProblem")]
        [InlineData("routing-failed", "insufficientData")]
        public void Every_assessment_survives_an_identical_private_network_name(string fixture, string assessment)
        {
            var s = Edit(fixture, t => Data(t, "wifi")["interfaces"] = new[] { ReportExplanations.Node("ssid", assessment) });
            var report = ReportFor(s).Masked(new PrivacyMasker(s));
            Assert.Contains(JsonValue.GetList(report.Root, "explanations"), e => Equals(JsonValue.Get(e, "assessment"), assessment));
            Assert.DoesNotContain(assessment, JsonValue.Serialize(JsonValue.Get(report.Root["sections"], "wifi")));
        }

        [Fact]
        public void Explanation_values_are_encoded_in_html_and_masking_does_not_modify_the_source()
        {
            const string evil = "<svg onload='attack'>";
            var s = Edit("vpn-expected", t => {
                var adapter = JsonValue.GetList(Data(t, "adapters"), "adapters").Single(a => JsonValue.AsInt(JsonValue.Get(a, "interfaceIndex")) == 9);
                JsonValue.AsObject(adapter)["name"] = evil;
            });
            var before = JsonValue.Serialize(s.Root);
            var report = ReportFor(s); var masked = report.Masked(new PrivacyMasker(s));
            Assert.DoesNotContain(evil, HtmlReport.Write(report));
            Assert.Contains("&lt;svg", HtmlReport.Write(report));
            Assert.Equal(before, JsonValue.Serialize(s.Root)); Assert.NotSame(report.Root, masked.Root);
        }

        [Theory]
        [InlineData("ru", "Возможная причина")]
        [InlineData("en", "Possible cause")]
        public void First_screen_has_localized_limits_without_json_and_legacy_report_still_renders(string language, string assessment)
        {
            var s = TestData.LoadSnapshot("vpn-conflict"); var r = ReportFor(s, language);
            var html = HtmlReport.Write(r);
            var first = html.Substring(html.IndexOf("class=\"explanation\"", StringComparison.Ordinal));
            first = first.Substring(0, first.IndexOf("<details>", StringComparison.Ordinal));
            Assert.Contains(assessment, first);
            Assert.Contains(System.Net.WebUtility.HtmlEncode((string)JsonValue.Get(Vpn(r), "primaryLimitation")), first);
            Assert.DoesNotContain("ExOverlap", html); Assert.DoesNotContain("<script", html);
            Assert.Contains("<table>", html);
            r.Root.Remove("explanations"); Assert.Contains("TunnelEye", HtmlReport.Write(r));
        }

        [Fact]
        public void Explanations_share_cached_facts_and_fail_without_destroying_main_report()
        {
            var s = TestData.LoadSnapshot("clean");
            var provider = new CountingFact();
            var catalog = new FactCatalog(new IFactProvider[] { provider, new AdapterFacts() });
            var rules = TestData.LoadRules().Rules.Where(r => r.Id == "vpn-conflict").ToArray();
            var analysis = new RuleEngine(catalog).Evaluate(s, rules);
            Report.Build(s, analysis); Assert.Equal(1, provider.Calls);
            provider = new CountingFact { Throw = true };
            catalog = new FactCatalog(new IFactProvider[] { provider, new AdapterFacts() });
            analysis = new RuleEngine(catalog).Evaluate(s, rules);
            var report = Report.Build(s, analysis);
            Assert.NotEmpty(JsonValue.GetList(report.Root, "checks"));
            Assert.Equal("insufficientData", JsonValue.Get(Vpn(report), "assessment"));
            var manual = new AnalysisResult(s.SnapshotId, analysis.Results, analysis.RuleErrors, analysis.EvaluationErrors);
            report = Report.Build(s, manual, "en");
            Assert.Contains("unavailable", JsonValue.Serialize(report.Root["explanations"]));
        }

        private sealed class CountingFact : IFactProvider
        {
            public string Name => "tunnel-route-overlaps";
            internal int Calls; internal bool Throw;
            public FactSet Build(FactContext context) { Calls++; if (Throw) throw new InvalidOperationException("synthetic"); return FactSet.Create(Name); }
        }
    }
}
