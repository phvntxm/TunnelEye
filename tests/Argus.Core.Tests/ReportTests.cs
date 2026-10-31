// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Engine;
using Argus.Core.Json;
using Argus.Core.Reports;
using Argus.Core.Rules;
using Argus.Core.Snapshots;
using Xunit;

namespace Argus.Core.Tests
{
    public class ReportTests
    {
        private static Report Build(string name, string lang = "ru")
        {
            var s = TestData.LoadSnapshot(name);
            return Report.Build(s, TestData.Analyze(s), lang);
        }
        private static string Score(Report r) => (string)JsonValue.Get(r.Root["summary"], "score");

        [Theory]
        [InlineData("clean", "green")]
        [InlineData("dead-proxy", "red")]
        [InlineData("two-gateways", "yellow")]
        [InlineData("routing-failed", "gray")]
        [InlineData("dead-proxy-other-user", "gray")]
        [InlineData("wfp-conflict", "green")]
        public void Score_respects_severity_experiments_and_incomplete_critical_checks(string name, string expected)
        { Assert.Equal(expected, Score(Build(name))); }

        [Fact]
        public void Loader_errors_and_an_empty_ruleset_cannot_produce_green()
        {
            var s = TestData.LoadSnapshot("clean");
            var a = TestData.Analyze(s);
            Assert.Equal("gray", Score(Report.Build(s, new AnalysisResult(s.SnapshotId, a.Results, new[] { "broken rule" }, new string[0]))));
            Assert.Equal("gray", Score(Report.Build(s, new AnalysisResult(s.SnapshotId, new RuleResult[0], new string[0], new string[0]))));
        }

        [Fact]
        public void A_skipped_wifi_module_is_not_applicable_and_has_no_module_error()
        {
            var t = TestData.LoadTree("clean");
            var wifi = JsonValue.AsObject(JsonValue.Get(t["modules"], "wifi"));
            wifi["status"] = "skipped"; wifi["data"] = null;
            wifi["errors"] = JsonValue.Parse(@"[{""source"":""wlan"",""kind"":""NotSupported"",""message"":""No adapter""}]");
            var s = Snapshot.Parse(JsonValue.Serialize(t));
            var r = Report.Build(s, TestData.Analyze(s));
            var check = JsonValue.GetList(r.Root, "checks").Single(c => Equals(JsonValue.Get(c, "id"), "wifi-weak-signal"));
            Assert.Equal("notApplicable", JsonValue.Get(check, "status"));
            var m = JsonValue.GetList(r.Root, "modules").Single(c => Equals(JsonValue.Get(c, "name"), "wifi"));
            Assert.Empty(JsonValue.GetList(m, "errors"));
        }

        [Theory]
        [InlineData("ru", "Главные рекомендации")]
        [InlineData("en", "Top recommendations")]
        public void Html_is_localized_offline_and_has_no_active_content(string lang, string label)
        {
            var html = HtmlReport.Write(Build("dead-proxy", lang));
            Assert.Contains(label, html);
            Assert.Contains("default-src 'none'; style-src 'unsafe-inline'; img-src data:", html);
            Assert.Contains("<svg", html); Assert.Contains("<details>", html);
            Assert.DoesNotContain("<script", html.ToLowerInvariant());
            Assert.DoesNotContain("src=\"http", html); Assert.DoesNotContain("href=\"http", html);
        }

        [Fact]
        public void Snapshot_strings_are_encoded_including_svg_payloads()
        {
            const string evil = "\"><svg onload=\"alert(1)\"><script>attack</script>&";
            var t = TestData.LoadTree("hosts-sensitive");
            var data = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(t["modules"], "wifi"), "data"));
            data["interfaces"] = new object[] { new Dictionary<string, object> { ["ssid"] = evil } };
            var s = Snapshot.Parse(JsonValue.Serialize(t));
            var html = HtmlReport.Write(Report.Build(s, TestData.Analyze(s)));
            Assert.DoesNotContain(evil, html);
            Assert.DoesNotContain("<script", html.ToLowerInvariant());
            Assert.Contains("attack", html);
            Assert.True(html.Contains("&lt;svg") || html.Contains(@"<svg"));
            // Event-like text can exist as encoded inert text, never as attributes.
            Assert.DoesNotContain("<svg onload", html);
            Assert.DoesNotMatch(@"\son\w+\s*=", html);
        }

        [Fact]
        public void Common_private_values_do_not_corrupt_protocol_identifiers()
        {
            var t = TestData.LoadTree("clean");
            var wifi = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(t["modules"], "wifi"), "data"));
            wifi["interfaces"] = JsonValue.Parse(@"[{""ssid"":""ru""}]");
            var s = Snapshot.Parse(JsonValue.Serialize(t));
            var r = Report.Build(s, TestData.Analyze(s)).Masked(new PrivacyMasker(s));
            Assert.Equal("ru", r.Root["language"]);
            Assert.Equal(Report.Schema, r.Root["schema"]);
            Assert.Contains("SSID-1", r.Json());
            Assert.Contains("<html lang=\"ru\">", HtmlReport.Write(r));
        }

        [Fact]
        public void Editing_report_sections_does_not_modify_the_snapshot()
        {
            var s = TestData.LoadSnapshot("clean");
            var before = JsonValue.Serialize(s.Root);
            var report = Report.Build(s, TestData.Analyze(s));
            JsonValue.AsObject(JsonValue.Get(report.Root["sections"], "system"))["computer"] = null;
            Assert.Equal(before, JsonValue.Serialize(s.Root));
        }

        [Fact]
        public void Charts_keep_units_and_missing_rtt_is_not_zero()
        {
            var r = Build("clean");
            var charts = JsonValue.AsObject(r.Root["charts"]);
            Assert.Equal(2, JsonValue.AsList(charts["Latency"]).Count);
            Assert.Equal(3, JsonValue.AsList(charts["Losses"]).Count);
            Assert.Empty(JsonValue.AsList(charts["EventTimeline"]));
            Assert.Equal(4, JsonValue.AsList(charts["DnsLatency"]).Count);
        }

        [Fact]
        public void Masking_covers_report_snapshot_embedded_strings_and_keeps_hardware()
        {
            var t = TestData.LoadTree("clean");
            var modules = JsonValue.AsObject(t["modules"]);
            var system = JsonValue.AsObject(JsonValue.Get(modules["system"], "data"));
            system["computer"] = JsonValue.Parse(@"{""name"":""PRIVATE-PC"",""domain"":""private.corp""}");
            var wifi = JsonValue.AsObject(JsonValue.Get(modules["wifi"], "data"));
            wifi["interfaces"] = JsonValue.Parse(@"[{""ssid"":""PRIVATE-SSID"",""macAddress"":""AA-BB-CC-DD-EE-FF""}]");
            var vpn = JsonValue.AsObject(JsonValue.Get(modules["vpn"], "data"));
            vpn["builtIn"] = JsonValue.Parse(@"{""profiles"":[{""name"":""PRIVATE-VPN"",""serverAddress"":""vpn.private.example"",""servers"":[{""serverAddress"":""backup.private.example"",""friendlyName"":""PRIVATE-BACKUP""}]}]}");
            var dns = JsonValue.AsObject(JsonValue.Get(modules["dns-proxy"], "data"));
            dns["suffixSearchList"] = new[] { "corp.secret.example" };
            dns["proxy"] = JsonValue.Parse(@"{""user"":{""proxyServer"":""proxy.secret.example:8080"",""autoConfigUrl"":""https://pac.secret.example/config.pac""}}");
            system["testMessage"] = "PRIVATE-PC PRIVATE-SSID PRIVATE-VPN vpn.private.example 192.168.1.1 2001:db8::123 C:\\Users\\PrivateUser\\file";
            var s = Snapshot.Parse(JsonValue.Serialize(t));
            var original = JsonValue.Serialize(s.Root);
            var masker = new PrivacyMasker(s);
            var report = Report.Build(s, TestData.Analyze(s)).Masked(masker);
            var outputs = new[] { report.Json(), HtmlReport.Write(report), masker.SnapshotJson(s) };
            foreach (var output in outputs)
                foreach (var secret in new[] { "PRIVATE-PC", "PRIVATE-SSID", "PRIVATE-VPN", "vpn.private.example", "backup.private.example", "PRIVATE-BACKUP", "private.corp", "AA-BB-CC-DD-EE-FF", "192.168.1.1", "2001:db8::123", "PrivateUser", "corp.secret.example", "proxy.secret.example", "pac.secret.example" })
                    Assert.DoesNotContain(secret, output);
            var masked = JsonValue.Parse(masker.SnapshotJson(s));
            var mm = JsonValue.Get(masked, "modules");
            var route = JsonValue.GetList(JsonValue.Get(JsonValue.Get(mm, "routing"), "data"), "routes")[0];
            var gateway = JsonValue.GetList(JsonValue.Get(JsonValue.Get(mm, "connectivity"), "data"), "gateways")[0];
            Assert.Equal(JsonValue.Get(route, "nextHop"), JsonValue.Get(gateway, "address"));
            Assert.Equal(original, JsonValue.Serialize(s.Root));
            Assert.Contains("IP-", report.Json());
            Assert.Contains("Example", report.Json());
            Assert.Equal(Report.Schema, JsonValue.Get(JsonValue.Parse(report.Json()), "schema"));
            Assert.Equal(Snapshot.SnapshotSchema, JsonValue.Get(JsonValue.Parse(masker.SnapshotJson(s)), "schema"));
        }
    }
}

