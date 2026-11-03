// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Json;
using Argus.Core.Snapshots;

namespace Argus.Core.Reports
{
    /// <summary>Presentation of shared analysis facts, not a second rule evaluator.</summary>
    internal static class ReportExplanations
    {
        internal static Dictionary<string, object> Node(params object[] pairs)
        {
            var result = new Dictionary<string, object>(StringComparer.Ordinal);
            for (var i = 0; i < pairs.Length; i += 2) result.Add((string)pairs[i], pairs[i + 1]);
            return result;
        }

        private sealed class Card
        {
            internal readonly string Language;
            internal readonly List<object> Claims = new List<object>(), Evidence = new List<object>(), Nodes = new List<object>(), Edges = new List<object>();
            internal readonly List<string> Limitations = new List<string>();
            internal readonly Dictionary<string, object> Root;
            internal Card(string id, string language, string title)
            {
                Language = language;
                Root = Node("id", id, "ruleId", null, "placement", "configuration", "assessment", "insufficientData",
                    "title", T(title), "mechanism", T("ExUnknownMechanism"), "possibleSymptom", T("ExNoSymptom"),
                    "action", T("ExInspect"), "primaryLimitation", T("ExIncomplete"),
                    "claims", Claims, "evidence", Evidence, "path", Node("nodes", Nodes, "edges", Edges), "limitations", Limitations);
                Limitations.Add(T("ExTime"));
            }
            internal string T(string key, params object[] args) => string.Format(CultureInfo.InvariantCulture, ReportText.Get(key, Language), args);
            internal string Claim(string kind, bool known, string text, string scope, string evidenceKind, object values, params string[] sources)
            {
                var id = "claim-" + (Claims.Count + 1);
                var refs = new string[0];
                if (sources.Length > 0)
                {
                    var evidenceId = "evidence-" + (Evidence.Count + 1);
                    Evidence.Add(Node("id", evidenceId, "kind", evidenceKind, "sources", sources, "values", values));
                    refs = new[] { evidenceId };
                }
                Claims.Add(Node("id", id, "kind", kind, "availability", known ? "known" : "unknown",
                    "text", text, "scope", scope, "evidenceRefs", refs, "limitations", known ? new string[0] : new[] { T("ExIncomplete") }));
                return id;
            }
            internal string PathNode(string text, params string[] claims)
            {
                var id = "node-" + (Nodes.Count + 1);
                Nodes.Add(Node("id", id, "text", text, "claimRefs", claims)); return id;
            }
            internal void Edge(string from, string to, string kind, string text, params string[] claims) =>
                Edges.Add(Node("id", "edge-" + (Edges.Count + 1), "from", from, "to", to, "kind", kind, "text", text, "claimRefs", claims));
        }

        internal static object[] Build(Snapshot snapshot, AnalysisResult analysis, string language)
        {
            if (analysis.Facts == null || !ReferenceEquals(analysis.Facts.Snapshot, snapshot))
                return new object[] { Failure(language, "ExContextMissing") };
            var result = new List<object>();
            try { result.Add(Vpn(snapshot, analysis, language)); }
            catch (Exception) { result.Add(Failure(language, "ExBuildFailed")); }
            try { result.AddRange(Proxies(snapshot, analysis, language)); }
            catch (Exception) { result.Add(Failure(language, "ExBuildFailed", "proxy-explanation-error")); }
            return result.OrderBy(e => Equals(JsonValue.Get(e, "placement"), "finding") ? 0 : 1)
                .ThenBy(e => {
                    var rule = analysis.Results.FirstOrDefault(r => Equals(r.Rule.Id, JsonValue.Get(e, "ruleId")));
                    return rule == null ? int.MaxValue : (int)rule.Rule.Level;
                }).ToArray();
        }

        private static object Failure(string language, string reason, string id = "explanation-error")
        {
            var c = new Card(id, language, "ExUnavailable");
            c.Root["primaryLimitation"] = c.T(reason);
            c.Claim("derived", false, c.T(reason), c.T("ExConfiguration"), "section", null);
            return c.Root;
        }

        private static object Vpn(Snapshot snapshot, AnalysisResult analysis, string language)
        {
            var c = new Card("vpn-configuration", language, "ExVpnTitle");
            var context = analysis.Facts;
            var overlap = context.Get("tunnel-route-overlaps");
            var adapters = context.Get("adapters");
            var found = analysis.Results.Any(r => r.Rule.Id == "vpn-conflict" && r.Status == RuleStatus.Found);
            var complete = overlap.Available && overlap.Limitations.Count == 0;
            var scope = c.T("ExBroadScope");
            if (found)
            {
                c.Root["ruleId"] = "vpn-conflict"; c.Root["placement"] = "finding";
                c.Root["assessment"] = "possibleCause"; c.Root["title"] = c.T("ExOverlapTitle");
                c.Root["mechanism"] = c.T("ExOverlapMechanism"); c.Root["possibleSymptom"] = c.T("ExOverlapSymptom");
                c.Root["action"] = c.T("ExOverlapAction"); c.Root["primaryLimitation"] = c.T("ExCausality");
                foreach (var item in overlap.Items)
                    c.Claim("derived", true, c.T("ExOverlapClaim", item.Values["clientAId"], item.Values["clientBId"],
                        item.Values["family"], string.Join(", ", JsonValue.AsList(item.Values["overlapPrefixes"]))), scope, "row", item.Values, item.Evidence.ToArray());
                c.Claim("hypothesis", false, c.T("ExOverlapSymptom"), scope, "section", null);
            }
            else if (complete && overlap.Items.Count == 0)
            {
                c.Root["assessment"] = "expectedBehavior";
                c.Root["mechanism"] = c.T("ExRouteMechanism"); c.Root["action"] = c.T("ExVpnAction");
                c.Root["primaryLimitation"] = c.T("ExNotTraffic");
                c.Claim("derived", true, c.T("ExNoOverlap"), scope, "section", Node("limitations", overlap.Limitations),
                    "routing.routes", "routing.interfaces", "adapters.adapters", "vpn.clients");
            }
            else
            {
                c.Root["primaryLimitation"] = c.T("ExVpnIncomplete");
                c.Claim("derived", false, c.T("ExVpnIncomplete"), scope, "section",
                    Node("reason", overlap.UnavailableReason, "limitations", overlap.Limitations));
            }
            if (!complete) c.Limitations.Add(c.T("ExVpnIncomplete"));
            c.Limitations.Add(c.T("ExNotTraffic"));
            c.Limitations.Add(c.T("ExNoAuthorship"));
            foreach (var adapter in adapters.Items.Where(a => Equals(a.Values["isTunnel"], true) && Equals(a.Values["status"], "Up")))
            {
                var known = adapter.Values["identifiedClientId"] != null;
                c.Claim("observed", true, c.T("ExActiveInterface", adapter.Values["interfaceIndex"], adapter.Values["name"]),
                    scope, "row", adapter.Values, adapter.Evidence.ToArray());
                c.Claim("derived", known, c.T(known ? "ExInterfaceClient" : "ExInterfaceClientUnknown",
                    adapter.Values["interfaceIndex"], adapter.Values["identifiedClientName"]), scope, "row", adapter.Values, adapter.Evidence.ToArray());
            }
            var routing = snapshot.Module("routing");
            var data = routing != null && routing.IsUsable ? routing.Data : null;
            var routes = JsonValue.GetList(data, "routes");
            for (var i = 0; i < routes.Count; i++)
            {
                var row = routes[i];
                var adapter = AdapterFacts.Find(adapters, JsonValue.AsInt(JsonValue.Get(row, "interfaceIndex")));
                if (adapter == null || !Equals(adapter.Values["isTunnel"], true)) continue;
                c.Claim("observed", true, c.T("ExRoute", JsonValue.Get(row, "destinationPrefix"), JsonValue.Get(row, "interfaceIndex")),
                    c.T("ExRoutingScope"), "row", row, "routing.routes[" + i + "]");
            }
            var selections = JsonValue.GetList(data, "routeSelection");
            for (var i = 0; i < selections.Count; i++)
            {
                var s = selections[i];
                var index = JsonValue.AsInt(JsonValue.Get(s, "interfaceIndex"));
                if (index == null || JsonValue.AsBool(JsonValue.Get(s, "reachable")) != true) continue;
                var claim = c.Claim("observed", true, c.T("ExSelected", JsonValue.Get(s, "target"), index),
                    c.T("ExLocalSelectionScope"), "row", s, "routing.routeSelection[" + i + "]");
                if (!found && Equals(c.Root["title"], c.T("ExVpnTitle")))
                    c.Root["title"] = c.T("ExSelected", JsonValue.Get(s, "target"), index);
                var from = c.PathNode(c.T("ExLocalTable"), claim);
                var to = c.PathNode(c.T("ExInterface", index), claim);
                c.Edge(from, to, "locallySelected", c.T("ExSelectionLabel", JsonValue.Get(s, "target")), claim);
                var unknown = c.PathNode(c.T("ExUnknownBeyond"));
                c.Edge(to, unknown, "unknown", c.T("ExNotTraffic"), claim);
            }
            if (selections.Count == 0 || !selections.Any(s => JsonValue.AsInt(JsonValue.Get(s, "interfaceIndex")) != null && Equals(JsonValue.Get(s, "reachable"), true)))
                c.Claim("observed", false, c.T("ExSelectionUnknown"), c.T("ExLocalSelectionScope"), "section", null);
            var dns = snapshot.Module("dns-proxy");
            if (dns != null && dns.IsUsable && JsonValue.AsList(JsonValue.Get(dns.Data, "dnsServers")) != null)
            {
                var servers = JsonValue.GetList(dns.Data, "dnsServers");
                for (var i = 0; i < servers.Count; i++)
                {
                    var row = servers[i];
                    c.Claim("observed", true, c.T("ExDns", JsonValue.Get(row, "interfaceIndex"),
                        string.Join(", ", JsonValue.GetList(row, "serverAddresses"))), c.T("ExDnsScope"), "row", row, "dns-proxy.dnsServers[" + i + "]");
                }
            }
            if (!SectionEvidence.Complete(snapshot, "dns-proxy", "dnsServers"))
                c.Claim("observed", false, c.T("ExDnsUnknown"), c.T("ExDnsScope"), "section", null);
            c.Claim("recommendation", true, (string)c.Root["action"], scope, "section", null);
            return c.Root;
        }

        private static IEnumerable<object> Proxies(Snapshot snapshot, AnalysisResult analysis, string language)
        {
            var proxies = analysis.Facts.Get("proxies");
            if (!proxies.Available) return new[] { Failure(language, "ExProxyUnavailable", "proxy-unavailable") };
            var cards = new List<object>();
            for (var i = 0; i < proxies.Items.Count; i++)
            {
                var item = proxies.Items[i];
                var v = item.Values;
                var c = new Card("proxy-" + (i + 1), language, "ExProxyTitle");
                var source = JsonValue.AsString(v["source"]);
                var scope = c.T("ExProxyScope_" + source);
                var endpoint = v["host"] + ":" + v["port"];
                var effective = JsonValue.AsBool(v["effective"]);
                var status = JsonValue.AsString(v["tcpStatus"]);
                var listening = JsonValue.AsBool(v["listening"]);
                var rule = analysis.Results.FirstOrDefault(r => r.Rule.Id == "dead-proxy");
                var found = rule != null && rule.Status == RuleStatus.Found && rule.Evidence.Any(e =>
                    Equals(JsonValue.Get(e.Values, "source"), source) && Equals(JsonValue.Get(e.Values, "host"), v["host"]) && Equals(JsonValue.Get(e.Values, "port"), v["port"]));
                c.Root["title"] = c.T("ExProxyEndpoint", endpoint);
                if (status != null) c.Root["title"] += " · " + c.T("ExTcp_" + status);
                else if (listening == false) c.Root["title"] += " · " + c.T("ExListenerAbsent");
                c.Root["mechanism"] = c.T("ExProxyMechanism"); c.Root["possibleSymptom"] = c.T("ExProxySymptom");
                c.Root["primaryLimitation"] = c.T("ExProxyBoundary"); c.Root["action"] = c.T("ExProxyAction");
                c.Limitations.Add(c.T("ExProxyBoundary")); c.Limitations.Add(c.T("ExNoAuthorship"));
                var setting = c.Claim("observed", true, c.T("ExProxySetting", endpoint), scope, "row", v,
                    item.Evidence.Where(s => s.StartsWith("dns-proxy.", StringComparison.Ordinal)).ToArray());
                c.Claim("derived", effective != null, c.T(effective == true ? "ExProxyApplies" : effective == false ? "ExProxyDisabled" : "ExProxyScopeUnknown"), scope, "row",
                    Node("effective", effective), "dns-proxy.proxy." + source);
                var test = c.Claim("observed", status != null, c.T("ExTcp_" + (status ?? "unknown")), scope, "measurement",
                    Node("status", status), item.Evidence.Where(s => s.StartsWith("connectivity.", StringComparison.Ordinal)).ToArray());
                if (listening != null)
                    c.Claim("observed", true, c.T(listening == true ? "ExListenerPresent" : "ExListenerAbsent"), scope,
                        listening == true ? "row" : "section", Node("host", v["host"], "port", v["port"], "listening", listening),
                        item.Evidence.Where(s => s.StartsWith("connections.", StringComparison.Ordinal)).ToArray());
                else c.Claim("observed", false, c.T("ExListenerUnknown"), scope, "section", null);
                c.Claim("observed", v["process"] != null, c.T(v["process"] == null ? "ExOwnerUnknown" : "ExListenerOwner", v["process"], v["processId"]),
                    scope, "row", Node("process", v["process"], "processId", v["processId"]),
                    item.Evidence.Where(s => s.StartsWith("connections.tcpListeners[", StringComparison.Ordinal)).ToArray());
                if (found)
                {
                    c.Root["placement"] = "finding"; c.Root["ruleId"] = "dead-proxy";
                    c.Root["assessment"] = "confirmedConfigurationProblem";
                }
                else if (effective == false)
                {
                    c.Root["assessment"] = "expectedBehavior";
                    c.Root["action"] = c.T("ExVpnAction"); c.Root["possibleSymptom"] = c.T("ExNoSymptom");
                }
                if (effective == null) c.Root["primaryLimitation"] = c.T("ExProxyScopeUnknown");
                else if (status == null && listening != false && effective == true) c.Root["primaryLimitation"] = c.T("ExTcp_unknown");
                // A successful TCP connection says nothing about HTTP/SOCKS operation.
                if (status == "open") c.Root["primaryLimitation"] = c.T("ExTcp_open");
                c.Claim("hypothesis", false, (string)c.Root["possibleSymptom"], scope, "section", null);
                c.Claim("recommendation", true, (string)c.Root["action"], scope, "section", null);
                var app = c.PathNode(c.T("ExProxyApp"), setting);
                var proxy = c.PathNode(endpoint, setting);
                c.Edge(app, proxy, effective == true ? "configured" : "unknown", scope, setting);
                if (status != null)
                {
                    var probe = c.PathNode(c.T("ExTcpProbe"), test);
                    c.Edge(probe, proxy, "measured", c.T("ExTcp_" + status), test);
                }
                var beyond = c.PathNode(c.T("ExUnknownBeyond"));
                c.Edge(proxy, beyond, "unknown", c.T("ExProxyBoundary"));
                cards.Add(c.Root);
            }
            if (snapshot.ElevatedAsOtherUser)
                cards.Add(Failure(language, "ExOtherUser", "proxy-user-unknown"));
            if (cards.Count == 0 && (JsonValue.AsObject(JsonValue.Get(snapshot.Module("dns-proxy")?.Data, "proxy")) == null || proxies.Limitations.Count > 0))
                cards.Add(Failure(language, "ExProxyUnavailable", "proxy-unavailable"));
            return cards;
        }
    }
}
