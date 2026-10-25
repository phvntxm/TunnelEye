// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Json;
using Argus.Core.Rules;
using Argus.Core.Snapshots;
using Xunit;

namespace Argus.Core.Tests
{
    /// <summary>
    /// A failing fact or rule costs only itself, like a failing collector in
    /// stage 1 (review 007, fix 2). Plus the proxy fixes 3 and 4.
    /// </summary>
    public class IsolationTests
    {
        private sealed class BombFacts : IFactProvider
        {
            public string Name => "bomb";
            public FactSet Build(FactContext context) { throw new OverflowException("boom"); }
        }

        private sealed class TextFacts : IFactProvider
        {
            public string Name => "text";
            public FactSet Build(FactContext context)
            {
                var fact = FactSet.Create(Name);
                fact.Items.Add(new FactItem(new Dictionary<string, object> { ["s"] = new string('a', 40) + "!", ["n"] = 1 }, new[] { "test" }));
                return fact;
            }
        }

        private static string RuleJson(string id, string from, string where) =>
            "{\"schema\":\"tunneleye.rule/1\",\"id\":\"" + id + "\",\"level\":\"info\",\"facts\":[\"" + from + "\"]," +
            "\"condition\":{\"from\":\"" + from + "\",\"where\":" + where + "}," +
            "\"text\":{\"title\":{\"ru\":\"т\",\"en\":\"t\"},\"why\":{\"ru\":\"п\",\"en\":\"w\"},\"fix\":{\"ru\":\"и\",\"en\":\"f\"}}}";

        [Fact]
        public void A_failing_fact_or_rule_does_not_cost_the_others()
        {
            var catalog = new FactCatalog(new IFactProvider[] { new BombFacts(), new TextFacts() });
            var rules = new[]
            {
                RuleLoader.Parse(RuleJson("uses-bomb", "bomb", "{\"path\":\"x\",\"eq\":1}"), catalog),
                // Catastrophic backtracking: the 200 ms regex timeout fires.
                RuleLoader.Parse(RuleJson("slow-regex", "text", "{\"path\":\"s\",\"match\":\"^(a+)+$\"}"), catalog),
                RuleLoader.Parse(RuleJson("healthy", "text", "{\"path\":\"n\",\"eq\":1}"), catalog),
            };
            var analysis = new RuleEngine(catalog).Evaluate(TestData.LoadSnapshot("clean"), rules);

            var bomb = analysis.Results.Single(r => r.Rule.Id == "uses-bomb");
            Assert.Equal(RuleStatus.NotChecked, bomb.Status);
            Assert.Equal("fact-error:OverflowException", bomb.Reason);
            var slow = analysis.Results.Single(r => r.Rule.Id == "slow-regex");
            Assert.Equal(RuleStatus.NotChecked, slow.Status);
            Assert.Equal("rule-error:RegexMatchTimeoutException", slow.Reason);
            Assert.Equal(RuleStatus.Found, analysis.Results.Single(r => r.Rule.Id == "healthy").Status);
            Assert.Equal(2, analysis.EvaluationErrors.Count);
            Assert.Contains("\"evaluationErrors\"", AnalysisJson.Write(analysis));
        }

        [Theory]
        [InlineData("proxy.example:99999999999")]
        [InlineData("proxy.example:0")]
        [InlineData("proxy.example:65536")]
        public void An_out_of_range_port_does_not_throw(string value)
        {
            var entry = ProxyFacts.ParseProxyServer(value).Single();
            Assert.Equal("proxy.example", entry.Host);
            Assert.Null(entry.Port);
        }

        [Theory]
        [InlineData("0.0.0.0", "127.0.0.1", true)]
        [InlineData("127.0.0.1", "127.0.0.1", true)]
        [InlineData("::", "127.0.0.1", false)]
        [InlineData("::1", "127.0.0.1", false)]
        [InlineData("::", "::1", true)]
        [InlineData("0.0.0.0", "::1", false)]
        [InlineData("::1", "localhost", true)]
        [InlineData("127.0.0.1", "localhost", true)]
        public void A_listener_serves_only_hosts_of_its_family(string listener, string host, bool expected)
        {
            Assert.Equal(expected, ProxyFacts.ServesHost(listener, host));
        }

        /// <summary>The clean snapshot with a user proxy, the given connectivity entry and listeners.</summary>
        private static Snapshot WithUserProxy(string proxyServer, string connectivityProxyJson, string listenersJson)
        {
            var tree = JsonValue.AsObject(JsonValue.Parse(File.ReadAllText(Path.Combine(TestData.SnapshotsDir, "clean.json"), Encoding.UTF8)));
            var modules = JsonValue.AsObject(tree["modules"]);
            var user = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(JsonValue.Get(modules["dns-proxy"], "data"), "proxy"), "user"));
            user["proxyEnable"] = true;
            user["proxyServer"] = proxyServer;
            JsonValue.AsObject(JsonValue.Get(modules["connectivity"], "data"))["proxies"] = JsonValue.Parse("[" + connectivityProxyJson + "]");
            JsonValue.AsObject(JsonValue.Get(modules["connections"], "data"))["tcpListeners"] = JsonValue.Parse(listenersJson);
            return Snapshot.Parse(JsonValue.Serialize(tree));
        }

        [Fact]
        public void A_proxy_on_127_0_0_1_with_an_ipv6_only_listener_is_dead()
        {
            var snapshot = WithUserProxy("127.0.0.1:8118", "", "[{\"localAddress\":\"::\",\"localPort\":8118}]");
            var r = TestData.Analyze(snapshot).Results.Single(x => x.Rule.Id == "dead-proxy");
            Assert.Equal(RuleStatus.Found, r.Status);
        }

        [Fact]
        public void An_untested_remote_proxy_is_a_limitation_not_a_clean_result()
        {
            var entry = "{\"source\":\"user\",\"enabled\":true,\"scheme\":null,\"host\":\"203.0.113.5\",\"port\":3128,\"addressClass\":\"public\",\"tested\":false,\"reason\":\"externalNotAllowed\",\"status\":null}";
            var r = TestData.Analyze(WithUserProxy("203.0.113.5:3128", entry, "[]")).Results.Single(x => x.Rule.Id == "dead-proxy");
            Assert.Equal(RuleStatus.NotFound, r.Status);
            Assert.Contains("proxy-not-tested:user:externalNotAllowed", r.Limitations);
        }
    }
}
