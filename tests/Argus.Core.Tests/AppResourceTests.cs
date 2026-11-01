// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using Argus.Core.Json;
using Argus.Core.Reports;
using TunnelEye.App;
using Xunit;

namespace Argus.Core.Tests
{
    public class AppResourceTests
    {
        [Fact]
        public void Window_resources_have_the_same_nonempty_keys_in_both_languages()
        {
            var keys = new List<HashSet<string>>();
            foreach (var suffix in new[] { "", ".en" })
            {
                var doc = new XmlDocument();
                doc.Load(Path.Combine(TestData.RepoRoot, "src", "TunnelEye.App", "Strings" + suffix + ".resx"));
                var set = new HashSet<string>();
                foreach (XmlElement node in doc.SelectNodes("/root/data"))
                { Assert.True(set.Add(node.GetAttribute("name"))); Assert.False(string.IsNullOrWhiteSpace(node["value"].InnerText)); }
                keys.Add(set);
            }
            Assert.True(keys[0].SetEquals(keys[1]));
            Assert.NotEqual(AppStrings.Get("WelcomeTitle", "ru"), AppStrings.Get("WelcomeTitle", "en"));
        }

        [Fact]
        public void Window_starts_without_elevation_and_does_not_require_admin_to_open_reports()
        {
            var doc = new XmlDocument();
            doc.Load(Path.Combine(TestData.RepoRoot, "src", "TunnelEye.App", "app.manifest"));
            var manager = new XmlNamespaceManager(doc.NameTable);
            manager.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v3");
            Assert.Equal("asInvoker", doc.SelectSingleNode("//asm:requestedExecutionLevel", manager).Attributes["level"].Value);
        }

        [Fact]
        public void Wifi_channel_utilization_is_available_to_both_export_and_window()
        {
            var tree = TestData.LoadTree("clean");
            var wifi = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(tree["modules"], "wifi"), "data"));
            wifi["neighbors"] = JsonValue.Parse(@"{""bss"":[{""bandGHz"":""2.4"",""channel"":6,""signalPercent"":55,""channelUtilizationPercent"":72}]}");
            var snapshot = Snapshots.Snapshot.Parse(JsonValue.Serialize(tree));
            var report = Report.Build(snapshot, TestData.Analyze(snapshot));
            var points = JsonValue.GetList(report.Root["charts"], "WifiUtilization");
            Assert.Single(points);
            Assert.Equal(72, JsonValue.AsInt(JsonValue.Get(points[0], "value")));
            Assert.Contains(ReportText.Get("WifiUtilization", "ru"), HtmlReport.Write(report));
        }
    }
}
