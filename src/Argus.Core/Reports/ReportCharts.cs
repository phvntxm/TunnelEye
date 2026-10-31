// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Argus.Core.Json;
using Argus.Core.Snapshots;

namespace Argus.Core.Reports
{
    internal static class ReportCharts
    {
        internal static object Build(Snapshot snapshot)
        {
            var charts = new Dictionary<string, object>();
            var latency = new List<object>(); var losses = new List<object>(); var dns = new List<object>();
            var connectivity = snapshot.Module("connectivity")?.Data;
            foreach (var g in JsonValue.GetList(connectivity, "gateways"))
                Ping(g, JsonValue.Get(g, "ping"), "address", latency, losses);
            var external = JsonValue.Get(connectivity, "external");
            foreach (var p in JsonValue.GetList(external, "ping")) Ping(p, JsonValue.Get(p, "result"), "target", latency, losses);
            foreach (var query in JsonValue.GetList(external, "dns"))
                foreach (var response in JsonValue.GetList(query, "results"))
                    Point(dns, JsonValue.Get(query, "name") + " / " + JsonValue.Get(response, "server") + " / " + JsonValue.Get(response, "status"), JsonValue.Get(response, "rttMs"));
            charts["Latency"] = latency; charts["Losses"] = losses; charts["DnsLatency"] = dns;
            var wifi = new List<object>();
            foreach (var bss in JsonValue.GetList(JsonValue.Get(snapshot.Module("wifi")?.Data, "neighbors"), "bss"))
                Point(wifi, JsonValue.Get(bss, "bandGHz") + " / " + JsonValue.Get(bss, "channel"), JsonValue.Get(bss, "signalPercent"));
            charts["WifiChannels"] = wifi;
            var days = new SortedDictionary<string, int>(StringComparer.Ordinal);
            foreach (var group in JsonValue.GetList(snapshot.Module("events")?.Data, "groups"))
                foreach (var time in JsonValue.GetList(group, "times"))
                {
                    DateTime date;
                    if (!DateTime.TryParse(JsonValue.AsString(time), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out date)) continue;
                    var key = date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                    int count; days.TryGetValue(key, out count); days[key] = count + 1;
                }
            var events = new List<object>(); foreach (var day in days) Point(events, day.Key, day.Value);
            charts["EventTimeline"] = events;
            return charts;
        }
        private static void Ping(object owner, object ping, string key, List<object> latency, List<object> losses)
        {
            var label = JsonValue.Get(owner, key) + " / " + JsonValue.Get(owner, "viaInterfaceAlias");
            Point(latency, label, JsonValue.Get(ping, "rttAvgMs")); Point(losses, label, JsonValue.Get(ping, "lossPercent"));
        }
        private static void Point(List<object> points, string label, object value)
        {
            if (!JsonValue.IsNumber(value)) return;
            double n = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            if (double.IsNaN(n) || double.IsInfinity(n) || n < 0) return;
            points.Add(new Dictionary<string, object> { ["label"] = label, ["value"] = n });
        }
    }
}
