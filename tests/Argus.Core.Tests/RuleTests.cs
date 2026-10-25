// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.IO;
using System.Linq;
using System.Text;
using Argus.Core.Facts;
using Argus.Core.Rules;
using Xunit;

namespace Argus.Core.Tests
{
    public class RuleTests
    {
        private const string Valid = @"{
  ""schema"": ""tunneleye.rule/1"", ""id"": ""sample"", ""level"": ""advice"",
  ""facts"": [""proxies""],
  ""thresholds"": { ""n"": 1 },
  ""condition"": { ""from"": ""proxies"", ""where"": { ""path"": ""port"", ""gte"": ""$threshold.n"" } },
  ""text"": { ""title"": { ""ru"": ""т"", ""en"": ""t"" }, ""why"": { ""ru"": ""п"", ""en"": ""w"" }, ""fix"": { ""ru"": ""и"", ""en"": ""f"" } }
}";

        private static Rule Parse(string json) => RuleLoader.Parse(json, FactCatalog.CreateDefault());

        [Fact]
        public void Every_repository_rule_loads_with_both_languages()
        {
            var loaded = TestData.LoadRules();
            Assert.Empty(loaded.Errors);
            Assert.True(loaded.Rules.Count >= 3);
            foreach (var rule in loaded.Rules)
            {
                foreach (var key in new[] { "title", "why", "fix" })
                {
                    Assert.False(string.IsNullOrWhiteSpace(rule.Text[key].Ru), rule.Id + "." + key + ".ru");
                    Assert.False(string.IsNullOrWhiteSpace(rule.Text[key].En), rule.Id + "." + key + ".en");
                }
            }
        }

        [Fact]
        public void A_match_pattern_may_be_a_threshold_and_is_checked_at_load()
        {
            var rule = Valid.Replace(@"""n"": 1", @"""p"": ""^(a|b)\\.example$""").Replace(@"""path"": ""port"", ""gte"": ""$threshold.n""", @"""path"": ""host"", ""match"": ""$threshold.p""");
            var parsed = Parse(rule);
            var context = new EvaluationContext(parsed.Thresholds, System.DateTime.UtcNow);
            Assert.Equal(Truth.True, parsed.Condition.Where.Test(new System.Collections.Generic.Dictionary<string, object> { ["host"] = "B.example" }, context));
            Assert.Equal(Truth.False, parsed.Condition.Where.Test(new System.Collections.Generic.Dictionary<string, object> { ["host"] = "$threshold.p" }, context));
            Assert.Throws<RuleFormatException>(() => Parse(rule.Replace(@"^(a|b)\\.example$", "(")));
            Assert.Throws<RuleFormatException>(() => Parse(rule.Replace(@"""^(a|b)\\.example$""", "5")));
        }

        [Fact]
        public void Rule_files_are_utf8_without_bom()
        {
            foreach (var path in Directory.GetFiles(TestData.RulesDir, "*.json"))
            {
                var bytes = File.ReadAllBytes(path);
                Assert.False(bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF, Path.GetFileName(path));
                Assert.NotNull(new UTF8Encoding(false, true).GetString(bytes));
            }
        }

        [Fact]
        public void Parses_a_valid_rule()
        {
            var rule = Parse(Valid);
            Assert.Equal("sample", rule.Id);
            Assert.Equal(RuleLevel.Advice, rule.Level);
            Assert.Equal("t", rule.Text["title"].For("en-US"));
            Assert.Equal("т", rule.Text["title"].For("ru-RU"));
        }

        [Theory]
        [InlineData("\"en\": \"t\"", "\"en\": \"\"")]                           // missing English text
        [InlineData("\"level\": \"advice\"", "\"level\": \"urgent\"")]           // unknown level
        [InlineData("\"facts\": [\"proxies\"]", "\"facts\": [\"nope\"]")]        // unknown fact
        [InlineData("\"$threshold.n\"", "\"$threshold.missing\"")]               // undeclared threshold
        [InlineData("\"id\": \"sample\"", "\"id\": \"Sample Rule\"")]            // bad id
        [InlineData("\"from\": \"proxies\"", "\"from\": \"adapters\"")]          // from must be a declared fact
        [InlineData("\"schema\": \"tunneleye.rule/1\",", "\"schema\": \"tunneleye.rule/1\", \"extra\": 1,")]
        public void Rejects_invalid_rules(string from, string to)
        {
            Assert.Throws<RuleFormatException>(() => Parse(Valid.Replace(from, to)));
        }

        [Fact]
        public void An_experimental_rule_cannot_be_above_advice()
        {
            var json = Valid.Replace("\"level\": \"advice\"", "\"level\": \"important\", \"experimental\": true");
            Assert.Throws<RuleFormatException>(() => Parse(json));
            Assert.True(Parse(Valid.Replace("\"level\": \"advice\"", "\"level\": \"advice\", \"experimental\": true")).Experimental);
        }

        [Fact]
        public void A_broken_file_does_not_stop_the_others()
        {
            var dir = Path.Combine(Path.GetTempPath(), "argus-rules-" + System.Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                File.WriteAllText(Path.Combine(dir, "sample.json"), Valid);
                File.WriteAllText(Path.Combine(dir, "broken.json"), "{ not json");
                File.WriteAllText(Path.Combine(dir, "other-name.json"), Valid);
                var loaded = RuleLoader.LoadDirectory(dir, FactCatalog.CreateDefault());
                Assert.Single(loaded.Rules);
                Assert.Equal(2, loaded.Errors.Count);
                Assert.Contains(loaded.Errors, e => e.StartsWith("broken.json"));
                Assert.Contains(loaded.Errors, e => e.StartsWith("other-name.json") && e.Contains("File name"));
            }
            finally { Directory.Delete(dir, true); }
        }

        [Theory]
        [InlineData("127.0.0.1:8118", null, "127.0.0.1", 8118)]
        [InlineData("http=10.0.0.5:3128;https=10.0.0.5:3129", "http", "10.0.0.5", 3128)]
        [InlineData("http://proxy.example:8080/", "http", "proxy.example", 8080)]
        [InlineData("socks=[::1]:1080", "socks", "::1", 1080)]
        [InlineData("proxy.example", null, "proxy.example", null)]
        public void Parses_proxy_server_strings(string value, string scheme, string host, int? port)
        {
            var first = ProxyFacts.ParseProxyServer(value).First();
            Assert.Equal(scheme, first.Scheme);
            Assert.Equal(host, first.Host);
            Assert.Equal(port, first.Port);
        }
    }
}
