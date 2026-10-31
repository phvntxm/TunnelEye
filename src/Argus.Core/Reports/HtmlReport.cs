// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using Argus.Core.Json;

namespace Argus.Core.Reports
{
    public static class HtmlReport
    {
        // The only path from a dynamic value to HTML/SVG text (D-015).
        private static string H(object value) => WebUtility.HtmlEncode(Convert.ToString(value, CultureInfo.InvariantCulture)).Replace("=", "&#61;");
        private static void DrawChart(StringBuilder b, string name, System.Collections.Generic.IList<object> points, string lang)
        {
            b.Append("<h3>").Append(H(ReportText.Get(name, lang))).Append("</h3>");
            if (points == null || points.Count == 0) { b.Append("<p>").Append(H(ReportText.Get("NoData", lang))).Append("</p>"); return; }
            var max = Math.Max(1, points.Max(p => Convert.ToDouble(JsonValue.Get(p, "value"), CultureInfo.InvariantCulture)));
            b.Append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1000 ").Append(points.Count * 38 + 12).Append("\" role=\"img\"><title>").Append(H(ReportText.Get(name, lang))).Append("</title>");
            int y = 25;
            foreach (var point in points)
            {
                var value = Convert.ToDouble(JsonValue.Get(point, "value"), CultureInfo.InvariantCulture);
                b.Append("<text x=\"4\" y=\"").Append(y).Append("\" font-size=\"13\">").Append(H(JsonValue.Get(point, "label"))).Append("</text><rect x=\"480\" y=\"").Append(y - 15).Append("\" width=\"").Append((value / max * 420).ToString("0.##", CultureInfo.InvariantCulture)).Append("\" height=\"20\" fill=\"#4669aa\"/><text x=\"920\" y=\"").Append(y).Append("\">").Append(H(value)).Append("</text>");
                y += 38;
            }
            b.Append("</svg>");
        }

        public static string Write(Report report)
        {
            var root = report.Root;
            var lang = (string)root["language"];
            Func<string, string> t = key => H(ReportText.Get(key, lang));
            var summary = JsonValue.AsObject(root["summary"]);
            var checks = JsonValue.GetList(root, "checks");
            var b = new StringBuilder("<!doctype html><html lang=\"");
            b.Append(H(lang)).Append("\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\"><title>TunnelEye</title><style>body{font:16px system-ui,sans-serif;max-width:1080px;margin:auto;padding:24px;background:#f3f5f8;color:#182438}article,section{background:white;border-radius:12px;padding:20px;margin:16px 0}h1,h2{line-height:1.3}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}summary{cursor:pointer}svg{width:100%;height:auto}table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:8px;border-bottom:1px solid #ddd}.red{border-left:8px solid #c63545}.yellow{border-left:8px solid #d39a16}.green{border-left:8px solid #21865a}.gray{border-left:8px solid #79818f}.muted{color:#536175}li{margin:8px 0}</style></head><body><h1>TunnelEye В· Argus</h1>");
            b.Append("<p>").Append(H(root["createdAt"])).Append(" В· ").Append(t("Version")).Append(' ').Append(H(root["version"])).Append("</p>");
            if (Equals(root["masked"], true)) b.Append("<p>").Append(t("Masked")).Append("</p>");
            b.Append("<section class=\"").Append(H(summary["score"])).Append("\"><h2>").Append(t("Score_" + summary["score"])).Append("</h2>");
            b.Append("<p>").Append(t("Scope")).Append("</p>");
            var counts = JsonValue.AsObject(summary["counts"]);
            b.Append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 680 160\" role=\"img\"><title>").Append(t("Counts")).Append("</title>");
            var max = Math.Max(1, counts.Values.Max(v => Convert.ToInt32(v, CultureInfo.InvariantCulture)));
            int y = 24;
            foreach (var pair in counts)
            {
                var n = Convert.ToInt32(pair.Value, CultureInfo.InvariantCulture);
                b.Append("<text x=\"4\" y=\"").Append(y).Append("\">").Append(t("Level_" + pair.Key)).Append("</text><rect x=\"150\" y=\"").Append(y - 16).Append("\" width=\"").Append(n * 430 / max).Append("\" height=\"20\" fill=\"#4669aa\"/><text x=\"610\" y=\"").Append(y).Append("\">").Append(n).Append("</text>");
                y += 36;
            }
            b.Append("</svg><h3>").Append(t("Recommendations")).Append("</h3><ol>");
            foreach (var id in JsonValue.GetList(summary, "recommendations"))
            {
                var check = checks.Single(c => Equals(JsonValue.Get(c, "id"), id));
                b.Append("<li>").Append(H(JsonValue.Get(check, "fix"))).Append("</li>");
            }
            b.Append("</ol></section><h2>").Append(t("Findings")).Append("</h2>");
            foreach (var check in checks.Where(c => Equals(JsonValue.Get(c, "status"), "found")))
            {
                b.Append("<article><p class=\"muted\">").Append(t("Level_" + JsonValue.Get(check, "level")));
                if (Equals(JsonValue.Get(check, "experimental"), true)) b.Append(" В· ").Append(t("Experimental"));
                b.Append("</p><h3>").Append(H(JsonValue.Get(check, "title"))).Append("</h3><p>").Append(H(JsonValue.Get(check, "why"))).Append("</p><p><strong>").Append(t("Fix")).Append("</strong> ").Append(H(JsonValue.Get(check, "fix"))).Append("</p>");
                b.Append("<details><summary>").Append(t("Evidence")).Append(" (").Append(H(JsonValue.Get(check, "evidenceCount"))).Append(")</summary><p>").Append(H(JsonValue.Get(check, "details"))).Append("</p>");
                // Hundreds of hosts names share one address: one collapsed group per address.
                var groups = JsonValue.GetList(check, "evidence").GroupBy(e => JsonValue.AsString(JsonValue.Get(JsonValue.Get(e, "values"), "address")) ?? "");
                foreach (var group in groups)
                    b.Append("<details><summary>").Append(H(group.Key)).Append(" В· ").Append(group.Count()).Append("</summary><pre>").Append(H(JsonValue.Serialize(group.ToArray()))).Append("</pre></details>");
                b.Append("</details></article>");
            }
            b.Append("<section><h2>").Append(t("Coverage")).Append("</h2>");
            foreach (var check in checks.Where(c => !Equals(JsonValue.Get(c, "status"), "found") || JsonValue.GetList(c, "limitations").Count > 0))
            {
                b.Append("<details><summary>").Append(H(JsonValue.Get(check, "title"))).Append(" В· ").Append(t("Status_" + JsonValue.Get(check, "status"))).Append("</summary><p>").Append(H(JsonValue.Get(check, "hint"))).Append("</p><pre>").Append(H(JsonValue.Serialize(new { reason = JsonValue.Get(check, "reason"), limitations = JsonValue.Get(check, "limitations") }))).Append("</pre></details>");
            }
            b.Append("</section>");
            b.Append("<section><h2>").Append(t("Charts")).Append("</h2><p>").Append(t("ChartScope")).Append("</p>");
            foreach (var chart in JsonValue.AsObject(root["charts"]))
                DrawChart(b, chart.Key, JsonValue.AsList(chart.Value), lang);
            b.Append("</section>");
            var sections = JsonValue.AsObject(root["sections"]);
            foreach (var section in new[] { "Network", "Services", "Hardware", "Appendix" })
            {
                b.Append("<section><h2>").Append(t(section)).Append("</h2>");
                if (section == "Network")
                {
                    object routing;
                    sections.TryGetValue("routing", out routing);
                    var routes = JsonValue.GetList(routing, "routes");
                    b.Append("<h3>").Append(t("RouteMap")).Append("</h3>");
                    // One row per route. Technical labels are encoded just like HTML values.
                    b.Append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1000 ").Append(Math.Max(50, routes.Count * 42)).Append("\" role=\"img\"><title>").Append(t("RouteMap")).Append("</title>");
                    int row = 26;
                    foreach (var route in routes)
                    {
                        b.Append("<text x=\"8\" y=\"").Append(row).Append("\" font-size=\"13\">").Append(H(JsonValue.Get(route, "interfaceAlias"))).Append(" → ").Append(H(JsonValue.Get(route, "nextHop"))).Append(" → ").Append(H(JsonValue.Get(route, "destinationPrefix"))).Append("</text>");
                        row += 42;
                    }
                    b.Append("</svg>");
                }
                string[] names = section == "Network" ? new[] { "adapters", "routing", "dns-proxy", "vpn", "firewall", "wifi", "connectivity", "connections", "tcp-stack" } : section == "Services" ? new[] { "services", "events" } : section == "Hardware" ? new[] { "hardware" } : new[] { "system" };
                foreach (var name in names)
                {
                    object data;
                    if (!sections.TryGetValue(name, out data)) continue;
                    b.Append("<details><summary>").Append(t("Module_" + name)).Append("</summary><pre>").Append(H(JsonValue.Serialize(data))).Append("</pre></details>");
                }
                if (section == "Appendix")
                {
                    b.Append("<table><tr><th>").Append(t("Module")).Append("</th><th>").Append(t("Status")).Append("</th></tr>");
                    foreach (var m in JsonValue.GetList(root, "modules"))
                        b.Append("<tr><td>").Append(t("Module_" + JsonValue.Get(m, "name"))).Append("</td><td>").Append(t("ModuleStatus_" + JsonValue.Get(m, "status"))).Append("<pre>").Append(H(JsonValue.Serialize(JsonValue.Get(m, "errors")))).Append("</pre></td></tr>");
                    b.Append("</table><pre>").Append(H(JsonValue.Serialize(root["ruleErrors"]))).Append('\n').Append(H(JsonValue.Serialize(root["evaluationErrors"]))).Append("</pre>");
                }
                b.Append("</section>");
            }
            return b.Append("</body></html>").ToString();
        }
    }
}
