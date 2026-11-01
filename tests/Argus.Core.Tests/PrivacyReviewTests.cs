// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Argus.Core.Json;
using Argus.Core.Reports;
using Argus.Core.Snapshots;
using Xunit;

namespace Argus.Core.Tests
{
    public class PrivacyReviewTests
    {
        private static IDictionary<string, object> ModuleData(IDictionary<string, object> tree, string name) =>
            JsonValue.AsObject(JsonValue.Get(JsonValue.Get(tree["modules"], name), "data"));

        private static object PathValue(object node, string path)
        {
            object value;
            Assert.True(JsonValue.TryGetPath(node, path, out value), "Missing test path: " + path);
            return value;
        }

        [Fact]
        public void Proxy_environment_bypass_lists_and_raw_copies_are_masked_in_every_export()
        {
            var tree = TestData.LoadTree("clean");
            var dns = ModuleData(tree, "dns-proxy");
            dns["proxy"] = JsonValue.Parse(@"{
                ""environment"": [
                    { ""name"":""HTTPS_PROXY"", ""value"":""http://private-env.example:8080"" },
                    { ""name"":""NO_PROXY"", ""value"":""localhost,.private-bypass.example"" }
                ],
                ""user"": { ""proxyOverride"":""*.private-override.example;<local>"" },
                ""winhttp"": { ""bypassList"":""private-list.example"", ""raw"":""private-env.example:8080 private-list.example"" }
            }");
            dns["nrpt"] = JsonValue.Parse(@"[{""namespace"":"".private-namespace.example"",""nameServers"":[] }]");
            dns["message"] = "private-override.example private-bypass.example private-namespace.example";
            var snapshot = Snapshot.Parse(JsonValue.Serialize(tree));
            var original = JsonValue.Serialize(snapshot.Root);
            var masker = new PrivacyMasker(snapshot);
            var report = Report.Build(snapshot, TestData.Analyze(snapshot)).Masked(masker);
            foreach (var output in new[] { masker.SnapshotJson(snapshot), report.Json(), HtmlReport.Write(report) })
                foreach (var name in new[] { "private-env.example", "private-bypass.example", "private-override.example", "private-list.example", "private-namespace.example" })
                    Assert.DoesNotContain(name, output);
            Assert.Equal(original, JsonValue.Serialize(snapshot.Root));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Nrpt_scalar_and_array_namespaces_and_server_hostnames_are_masked_consistently(bool namespaceIsArray)
        {
            const string privateNamespace = ".private-review.example";
            const string privateServer = "dns.other-review.example";
            var tree = TestData.LoadTree("clean");
            var dns = ModuleData(tree, "dns-proxy");
            dns["nrpt"] = new object[]
            {
                new Dictionary<string, object>
                {
                    ["namespace"] = namespaceIsArray ? (object)new[] { privateNamespace } : privateNamespace,
                    ["nameServers"] = new[] { privateServer },
                },
            };
            dns["message"] = privateNamespace + " " + privateServer;
            var snapshot = Snapshot.Parse(JsonValue.Serialize(tree));
            var original = JsonValue.Serialize(snapshot.Root);
            var masker = new PrivacyMasker(snapshot);
            var snapshotJson = masker.SnapshotJson(snapshot);
            var report = Report.Build(snapshot, TestData.Analyze(snapshot)).Masked(masker);
            var reportJson = report.Json();
            var html = HtmlReport.Write(report);
            foreach (var output in new[] { snapshotJson, reportJson, html })
            {
                Assert.DoesNotContain(privateNamespace, output);
                Assert.DoesNotContain(privateNamespace.TrimStart('.'), output);
                Assert.DoesNotContain(privateServer, output);
            }
            var snapshotEntry = PathValue(JsonValue.Parse(snapshotJson), "modules.dns-proxy.data.nrpt[0]");
            var reportEntry = PathValue(JsonValue.Parse(reportJson), "sections.dns-proxy.nrpt[0]");
            var maskedNamespace = JsonValue.Get(snapshotEntry, "namespace");
            var reportNamespace = JsonValue.Get(reportEntry, "namespace");
            if (namespaceIsArray)
            {
                maskedNamespace = JsonValue.AsList(maskedNamespace).Single();
                reportNamespace = JsonValue.AsList(reportNamespace).Single();
            }
            var maskedServer = JsonValue.GetList(snapshotEntry, "nameServers").Single();
            Assert.StartsWith("DNS-", (string)maskedNamespace);
            Assert.StartsWith("SERVER-", (string)maskedServer);
            Assert.Equal(maskedNamespace, reportNamespace);
            Assert.Equal(maskedServer, JsonValue.GetList(reportEntry, "nameServers").Single());
            Assert.Contains((string)maskedNamespace, html);
            Assert.Contains((string)maskedServer, html);
            var copiedText = PathValue(JsonValue.Parse(snapshotJson), "modules.dns-proxy.data.message");
            Assert.Equal(maskedNamespace + " " + maskedServer, copiedText);
            Assert.Equal(original, JsonValue.Serialize(snapshot.Root));
        }

        [Fact]
        public void An_ipv6_address_only_present_in_an_error_keeps_sentence_punctuation()
        {
            var masker = new PrivacyMasker(TestData.LoadSnapshot("clean"));
            var output = (string)masker.Transform("Failed at fd12:3456::42.");
            Assert.DoesNotContain("fd12:3456::42", output);
            Assert.StartsWith("Failed at IP-", output);
            Assert.EndsWith(".", output);
        }

        [Fact]
        public void Replacing_profile_paths_does_not_retokenize_generated_user_pseudonyms()
        {
            var tree = TestData.LoadTree("clean");
            tree["message"] = @"C:\Users\ExampleUser\file.txt";
            tree["otherMessage"] = "ExampleUser";
            var snapshot = Snapshot.Parse(JsonValue.Serialize(tree));
            var masker = new PrivacyMasker(snapshot);
            var masked = JsonValue.Parse(masker.SnapshotJson(snapshot));
            var user = (string)JsonValue.Get(masked, "otherMessage");
            Assert.StartsWith("USER-", user);
            Assert.Equal(@"C:\Users\" + user + @"\file.txt", JsonValue.Get(masked, "message"));
            Assert.Equal(JsonValue.Get(masked, "message"), masker.Transform(@"C:\Users\ExampleUser\file.txt"));
        }

        [Fact]
        public void Short_private_names_do_not_mutate_generated_address_tokens_or_hardware_models()
        {
            var tree = TestData.LoadTree("clean");
            ModuleData(tree, "wifi")["interfaces"] = JsonValue.Parse(@"[{""ssid"":""1""}]");
            var hardware = ModuleData(tree, "hardware");
            hardware["system"] = JsonValue.Parse(@"{""model"":""1""}");
            hardware["memory"] = JsonValue.Parse(@"{""modules"":[{""partNumber"":""MODEL-1-MEMORY""}]}");
            var snapshot = Snapshot.Parse(JsonValue.Serialize(tree));
            var masker = new PrivacyMasker(snapshot);
            var masked = JsonValue.Parse(masker.SnapshotJson(snapshot));
            var modules = JsonValue.Get(masked, "modules");
            Assert.Equal("1", PathValue(JsonValue.Get(JsonValue.Get(modules, "hardware"), "data"), "system.model"));
            Assert.Equal("MODEL-1-MEMORY", PathValue(JsonValue.Get(JsonValue.Get(modules, "hardware"), "data"), "memory.modules[0].partNumber"));
            Assert.Equal("SSID-1", PathValue(JsonValue.Get(JsonValue.Get(modules, "wifi"), "data"), "interfaces[0].ssid"));
            var address = (string)PathValue(JsonValue.Get(JsonValue.Get(modules, "routing"), "data"), "routes[0].nextHop");
            Assert.StartsWith("IP-", address);
            Assert.DoesNotContain("SSID", address);
            var report = Report.Build(snapshot, TestData.Analyze(snapshot)).Masked(masker);
            Assert.Equal("MODEL-1-MEMORY", PathValue(JsonValue.Get(report.Root["sections"], "hardware"), "memory.modules[0].partNumber"));
        }

        [Fact]
        public void Address_shaped_dictionary_keys_are_masked_together_with_their_values()
        {
            var snapshot = TestData.LoadSnapshot("clean");
            var masker = new PrivacyMasker(snapshot);
            var value = new Dictionary<string, object> { ["192.168.55.66"] = "192.168.55.66", ["AA-BB-CC-DD-EE-42"] = "AA-BB-CC-DD-EE-42" };
            var result = JsonValue.AsObject(masker.Transform(value));
            Assert.All(result, item => Assert.Equal(item.Key, item.Value));
            Assert.DoesNotContain("192.168.55.66", JsonValue.Serialize(result));
            Assert.DoesNotContain("AA-BB-CC-DD-EE-42", JsonValue.Serialize(result));
        }

        [Fact]
        public void Canonical_address_aliases_do_not_overwrite_dictionary_entries()
        {
            var masker = new PrivacyMasker(TestData.LoadSnapshot("clean"));
            var input = new Dictionary<string, object> { ["fd12:3456::42"] = 1, ["fd12:3456:0:0:0:0:0:42"] = 2 };
            var output = JsonValue.AsObject(masker.Transform(input));
            Assert.Equal(2, output.Count);
            Assert.Contains(1, output.Values);
            Assert.Contains(2, output.Values);
            Assert.All(output.Keys, key => Assert.StartsWith("IP-", key));
        }

        [Fact]
        public void Equivalent_ipv6_and_mac_spellings_share_the_same_pseudonym()
        {
            var masker = new PrivacyMasker(TestData.LoadSnapshot("clean"));
            var result = JsonValue.AsList(masker.Transform(new[] { "fd12:3456::42", "fd12:3456:0:0:0:0:0:42", "AA-BB-CC-DD-EE-42", "aa:bb:cc:dd:ee:42" }));
            Assert.Equal(result[0], result[1]);
            Assert.Equal(result[2], result[3]);
        }
    }
}
