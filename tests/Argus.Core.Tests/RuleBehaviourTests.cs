// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.Linq;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Json;
using Argus.Core.Rules;
using Argus.Core.Snapshots;
using Xunit;

namespace Argus.Core.Tests
{
    /// <summary>
    /// Edge cases of the stage 2.2 rules: what must not be found, and what
    /// must be "not checked" or carry a limitation instead of a clean result.
    /// </summary>
    public class RuleBehaviourTests
    {
        private static RuleResult Result(Snapshot snapshot, string ruleId) => TestData.Analyze(snapshot).Results.Single(r => r.Rule.Id == ruleId);

        private static RuleResult Result(string snapshot, string ruleId) => Result(TestData.LoadSnapshot(snapshot), ruleId);

        private static Snapshot Edit(string snapshot, System.Action<IDictionary<string, object>> edit)
        {
            var tree = TestData.LoadTree(snapshot);
            edit(tree);
            return Snapshot.Parse(JsonValue.Serialize(tree));
        }

        private static IDictionary<string, object> Data(IDictionary<string, object> tree, string module) =>
            JsonValue.AsObject(JsonValue.Get(JsonValue.Get(tree["modules"], module), "data"));

        private static FactSet Fact(Snapshot snapshot, string name) => FactCatalog.CreateDefault().CreateContext(snapshot).Get(name);

        // --- external tests (D-002) ---

        [Theory]
        [InlineData("routing-loop")]
        [InlineData("dns-spoofing")]
        public void Rules_on_external_tests_are_not_checked_without_consent(string ruleId)
        {
            var r = Result("external-not-run", ruleId);
            Assert.Equal(RuleStatus.NotChecked, r.Status);
            Assert.Equal("external-not-allowed", r.Reason);
        }

        [Fact]
        public void IPv6_past_a_full_tunnel_without_external_tests_is_a_limitation()
        {
            var snapshot = Edit("ipv6-bypass", t => Data(t, "connectivity")["external"] = null);
            var r = Result(snapshot, "ipv6-bypass");
            Assert.Equal(RuleStatus.NotFound, r.Status);
            Assert.Contains("ipv6-not-tested:externalNotAllowed", r.Limitations);
        }

        [Fact]
        public void A_repeated_hop_in_a_row_is_not_a_loop()
        {
            // clean: 203.0.113.1 answers TTL 3 and 4 - one router, not a circle.
            Assert.Equal(0, JsonValue.AsInt(Fact(TestData.LoadSnapshot("clean"), "traces").Items[0].Values["repeatedAddresses"]));
            Assert.Equal(2, JsonValue.AsInt(Fact(TestData.LoadSnapshot("routing-loop"), "traces").Items[0].Values["repeatedAddresses"]));
        }

        // --- VPN, DNS ---

        [Fact]
        public void A_dns_server_blocked_by_the_vpn_or_covered_by_nrpt_is_not_a_leak()
        {
            Assert.Equal(RuleStatus.NotFound, Result("full-tunnel", "dns-leak").Status);
            var nrpt = Edit("dns-leak", t => Data(t, "dns-proxy")["nrpt"] = JsonValue.Parse("[{\"namespace\":\".\",\"nameServers\":[\"10.8.0.1\"]}]"));
            Assert.Equal(RuleStatus.NotFound, Result(nrpt, "dns-leak").Status);
        }

        [Fact]
        public void An_untested_dns_server_under_a_full_tunnel_is_a_limitation()
        {
            var snapshot = Edit("dns-leak", t => Data(t, "connectivity")["dnsServers"] = new object[0]);
            var r = Result(snapshot, "dns-leak");
            Assert.Equal(RuleStatus.NotFound, r.Status);
            Assert.Contains("dns-path-not-tested:server-not-tested", r.Limitations);
        }

        [Fact]
        public void A_tunnel_without_default_routes_is_no_conflict()
        {
            // full-tunnel + an up WAN Miniport (clean) and wg0 only for its own prefix.
            var snapshot = Edit("vpn-conflict", t =>
            {
                var routes = JsonValue.AsList(Data(t, "routing")["routes"]).ToList();
                routes.RemoveAll(r => JsonValue.AsInt(JsonValue.Get(r, "interfaceIndex")) == 10);
                routes.Add(JsonValue.Parse("{\"addressFamily\":\"IPv4\",\"destinationPrefix\":\"10.0.0.0/24\",\"nextHop\":\"0.0.0.0\",\"interfaceIndex\":10,\"interfaceAlias\":\"wg0\",\"routeMetric\":0}"));
                Data(t, "routing")["routes"] = routes.ToArray();
            });
            Assert.Equal(RuleStatus.NotFound, Result(snapshot, "vpn-conflict").Status);
        }

        [Fact]
        public void A_vpn_service_without_a_file_is_a_vpn_leftover_not_a_generic_one()
        {
            var r = Result("vpn-service-missing", "vpn-leftovers");
            Assert.Equal("serviceWithoutFile", JsonValue.AsString(r.Evidence.Single().Values["kind"]));
            Assert.Equal(RuleStatus.NotFound, Result("vpn-service-missing", "missing-files").Status);
        }

        [Fact]
        public void A_wfp_provider_without_its_service_is_a_vpn_leftover()
        {
            var r = Result("orphaned-wfp-provider", "vpn-leftovers");
            var item = r.Evidence.Single();
            Assert.Equal("wfpProviderWithoutService", JsonValue.AsString(item.Values["kind"]));
            Assert.Equal("OldVpnSvc", JsonValue.AsString(item.Values["detail"]));
        }

        [Fact]
        public void Without_wfp_data_the_wfp_checks_are_not_checked()
        {
            var snapshot = Edit("clean", t => Data(t, "firewall")["wfp"] = null);
            var conflict = Result(snapshot, "wfp-conflict");
            Assert.Equal(RuleStatus.NotChecked, conflict.Status);
            Assert.Equal("wfp-not-collected", conflict.Reason);
            Assert.Contains("wfp-providers-not-checked:wfp-not-collected", Result(snapshot, "vpn-leftovers").Limitations);
        }

        [Fact]
        public void Windows_callouts_do_not_count_as_a_conflict()
        {
            // A Microsoft provider with a terminating callout next to one third party.
            var snapshot = Edit("wfp-conflict", t =>
            {
                var filters = JsonValue.AsList(JsonValue.Get(Data(t, "firewall")["wfp"], "filters"));
                JsonValue.AsObject(filters[1])["providerKey"] = "FWPM_PROVIDER_MPSSVC_WF";
            });
            Assert.Equal(RuleStatus.NotFound, Result(snapshot, "wfp-conflict").Status);
        }

        [Theory]
        [InlineData("0.0.0.0")]
        [InlineData("127.5.6.7")]
        [InlineData("::")]
        [InlineData("::1")]
        public void Blocked_sensitive_names_are_advice_not_redirection(string address)
        {
            var snapshot = Edit("hosts-sensitive-blocked", t =>
                JsonValue.AsObject(JsonValue.GetList(JsonValue.Get(Data(t, "dns-proxy"), "hosts"), "entries")[0])["address"] = address);
            Assert.Equal(RuleStatus.NotFound, Result(snapshot, "hosts-sensitive").Status);
            Assert.Equal(RuleStatus.Found, Result(snapshot, "hosts-sensitive-blocked").Status);
        }

        [Fact]
        public void Two_adapters_of_one_client_are_not_two_vpns()
        {
            var snapshot = Edit("vpn-conflict", t => Data(t, "vpn")["clients"] = JsonValue.Parse(
                @"[{""id"":""example-vpn"",""kind"":""vpn"",""adapters"":[{""interfaceIndex"":9},{""interfaceIndex"":10}]}]"));
            Assert.Equal(RuleStatus.NotFound, Result(snapshot, "vpn-conflict").Status);
            Assert.All(Fact(snapshot, "tunnels").Items, i => Assert.Equal(0, i.Values["otherClientsCapturingDefault"]));
        }

        [Theory]
        [InlineData("Disconnected")]
        [InlineData("Not Present")]
        public void Inactive_adapter_with_saved_routes_is_not_a_vpn_conflict(string status)
        {
            var snapshot = Edit("vpn-conflict", t => {
                var adapter = JsonValue.GetList(Data(t, "adapters"), "adapters").Single(a => JsonValue.AsInt(JsonValue.Get(a, "interfaceIndex")) == 10);
                JsonValue.AsObject(adapter)["status"] = status;
                Data(t, "routing")["interfaces"] = JsonValue.GetList(Data(t, "routing"), "interfaces")
                    .Where(i => JsonValue.AsInt(JsonValue.Get(i, "interfaceIndex")) != 10).ToArray();
            });
            Assert.Equal(RuleStatus.NotFound, Result(snapshot, "vpn-conflict").Status);
        }

        [Fact]
        public void Mandatory_ndis_filter_with_its_service_is_not_a_leftover()
        {
            var snapshot = Edit("ndis-filter-leftover", t => Data(t, "services")["drivers"] =
                JsonValue.Parse(@"[{""name"":""RemovedFilter"",""imageExists"":true}]"));
            Assert.Equal(RuleStatus.NotFound, Result(snapshot, "ndis-filter-leftover").Status);
        }

        // --- hosts ---

        [Fact]
        public void Both_hosts_rules_use_the_same_sensitive_list()
        {
            var rules = TestData.LoadRules().Rules;
            var a = rules.Single(r => r.Id == "hosts-sensitive").Thresholds["sensitiveNames"];
            var b = rules.Single(r => r.Id == "hosts-pinned").Thresholds["sensitiveNames"];
            Assert.Equal(a, b);
            Assert.Equal(a, rules.Single(r => r.Id == "hosts-sensitive-blocked").Thresholds["sensitiveNames"]);
        }

        [Theory]
        [InlineData("0.0.0.0", "update.microsoft.com", false)]
        [InlineData("203.0.113.1", "www.paypal.com", true)]
        [InlineData("203.0.113.1", "notpaypal.com", false)]
        [InlineData("203.0.113.1", "paypal.com.example", false)]
        public void Sensitive_names_match_by_domain_suffix(string address, string name, bool sensitive)
        {
            var snapshot = Edit("clean", t => JsonValue.AsObject(Data(t, "dns-proxy")["hosts"])["entries"] =
                JsonValue.Parse("[{\"address\":\"" + address + "\",\"names\":[\"" + name + "\"]}]"));
            Assert.Equal(sensitive ? RuleStatus.Found : RuleStatus.NotFound, Result(snapshot, "hosts-sensitive").Status);
        }

        // --- sharing ---

        [Fact]
        public void Without_administrator_rights_ics_is_found_by_its_scope_address()
        {
            var snapshot = Edit("clean", t =>
            {
                var routing = Data(t, "routing");
                routing["ics"] = JsonValue.Parse("{\"service\":{\"status\":\"Running\",\"startType\":\"Manual\",\"scopeAddress\":\"192.168.137.1\"},\"connections\":null}");
                var addresses = JsonValue.AsList(routing["addresses"]).ToList();
                addresses.Add(JsonValue.Parse("{\"interfaceIndex\":22,\"interfaceAlias\":\"Local Area Connection* 2\",\"addressFamily\":\"IPv4\",\"ipAddress\":\"192.168.137.1\"}"));
                routing["addresses"] = addresses.ToArray();
            });
            var r = Result(snapshot, "connection-sharing");
            Assert.Equal(RuleStatus.Found, r.Status);
            Assert.Contains("ics-connections-not-read", r.Limitations);
            Assert.Equal(true, r.Evidence.Single().Values["inferred"]);
        }

        // --- open ports ---

        [Fact]
        public void An_unread_firewall_filter_is_not_an_open_port()
        {
            var snapshot = Edit("open-ports", t => JsonValue.AsObject(JsonValue.AsList(Data(t, "firewall")["rules"])[1])["remoteAddresses"] = null);
            var r = Result(snapshot, "open-ports");
            Assert.Equal(RuleStatus.NotFound, r.Status);
            Assert.Contains("firewall-filters-not-read", r.Limitations);
        }

        [Fact]
        public void A_block_rule_wins_and_a_disabled_profile_opens_everything()
        {
            var blocked = Edit("open-ports", t =>
            {
                var rules = JsonValue.AsList(Data(t, "firewall")["rules"]).ToList();
                rules.Add(JsonValue.Parse("{\"name\":\"Block-7680\",\"enabled\":true,\"direction\":\"Inbound\",\"action\":\"Block\",\"profiles\":[\"Public\"],\"primaryStatus\":\"OK\",\"program\":\"Any\",\"service\":null,\"protocol\":\"TCP\",\"localPorts\":[\"7000-8000\"],\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}"));
                Data(t, "firewall")["rules"] = rules.ToArray();
            });
            Assert.Equal(RuleStatus.NotFound, Result(blocked, "open-ports").Status);

            var off = Edit("open-ports", t =>
            {
                Data(t, "firewall")["rules"] = new object[0];
                JsonValue.AsObject(JsonValue.AsList(Data(t, "firewall")["profiles"])[2])["enabled"] = false;
            });
            var r = Result(off, "open-ports");
            Assert.Equal(RuleStatus.Found, r.Status);
            Assert.Equal(2, r.Evidence.Count);
        }

        [Theory]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"7680\"],\"program\":\"C:\\\\Windows\\\\system32\\\\svchost.exe\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.True)]
        [InlineData("{\"protocol\":\"UDP\",\"localPorts\":[\"7680\"],\"program\":\"Any\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.False)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"7000-8000\"],\"program\":\"Any\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.True)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"RPC\"],\"program\":\"Any\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.False)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"Any\"],\"program\":\"C:\\\\Apps\\\\other.exe\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.False)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"Any\"],\"program\":\"Any\",\"package\":\"S-1-15-2-1\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.False)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"Any\"],\"program\":\"Any\",\"service\":\"DoSvc\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.Unknown)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":[\"Any\"],\"program\":\"Any\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"127.0.0.1\",\"::1\"]}", Truth.False)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":null,\"program\":\"Any\",\"localAddresses\":[\"Any\"],\"remoteAddresses\":[\"Any\"]}", Truth.Unknown)]
        [InlineData("{\"protocol\":\"TCP\",\"localPorts\":null,\"program\":\"C:\\\\Apps\\\\other.exe\",\"localAddresses\":null,\"remoteAddresses\":null}", Truth.False)]
        public void Firewall_rules_match_a_listener_in_three_valued_logic(string rule, Truth expected)
        {
            Assert.Equal(expected, ExposedPortFacts.Matches(JsonValue.Parse(rule), 7680, "svchost"));
        }

        // --- adapters ---

        [Fact]
        public void Only_physical_present_adapters_have_outdated_drivers()
        {
            var r = Result("outdated-driver", "outdated-driver");
            Assert.Equal("Ethernet", JsonValue.AsString(r.Evidence.Single().Values["name"]));
        }

        [Theory]
        [InlineData("Mobile", false)]
        [InlineData(null, true)]
        public void Power_saving_is_advice_only_on_a_desktop(string formFactor, bool limitation)
        {
            var snapshot = Edit("adapter-power-saving", t => JsonValue.AsObject(Data(t, "hardware")["system"])["pcSystemType"] = formFactor);
            var r = Result(snapshot, "adapter-power-saving");
            Assert.Equal(RuleStatus.NotFound, r.Status);
            Assert.Equal(limitation, r.Limitations.Any(l => l.StartsWith("form-factor-unknown:")));
        }

        [Fact]
        public void A_tunnel_mtu_and_mtu_zero_are_not_a_problem()
        {
            // clean has MTU = 0 in the registry; full-tunnel's tunnel is not a physical adapter.
            Assert.Null(Fact(TestData.LoadSnapshot("clean"), "interfaceMtu").Items.Single().Values["registryMtu"]);
            Assert.DoesNotContain(Fact(TestData.LoadSnapshot("full-tunnel"), "interfaceMtu").Items, i => JsonValue.AsInt(i.Values["interfaceIndex"]) == 9);
            Assert.Equal(1400, JsonValue.AsInt(Fact(TestData.LoadSnapshot("mtu-low"), "interfaceMtu").Items.Single().Values["registryMtu"]));
        }

        // --- Wi-Fi ---

        [Fact]
        public void Without_wifi_the_wifi_rules_are_not_checked()
        {
            var snapshot = Edit("clean", t =>
            {
                var wifi = JsonValue.AsObject(JsonValue.Get(t["modules"], "wifi"));
                wifi["status"] = "skipped";
                wifi["data"] = null;
            });
            Assert.Equal("module-skipped:wifi", Result(snapshot, "wifi-weak-signal").Reason);
        }

        [Theory]
        [InlineData("802.11ax", 6)]
        [InlineData("802.11AC", 5)]
        [InlineData("802.11n", 4)]
        [InlineData("802.11be", 7)]
        [InlineData("unknown", null)]
        public void Wifi_generations(string radioType, int? generation)
        {
            Assert.Equal(generation, WifiFacts.Generation(radioType));
        }

        [Theory]
        [InlineData(null, 6, "2.4")]
        [InlineData(null, 36, "5")]
        [InlineData("6", 37, "6")]
        [InlineData(null, null, null)]
        public void Wifi_band_falls_back_to_the_channel(string band, int? channel, string expected)
        {
            Assert.Equal(expected, WifiFacts.Band(band, channel));
        }

        // --- info ---

        [Fact]
        public void Info_findings_point_to_the_snapshot_header()
        {
            var r = Result("not-elevated", "not-elevated");
            Assert.Contains("host", r.Evidence.Single().Sources);
            Assert.Equal(RuleStatus.NotFound, Result("not-elevated", "external-not-run").Status);
        }
    }
}
