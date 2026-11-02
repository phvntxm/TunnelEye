// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Threading;
using Argus.Core.Json;
using Argus.Core.Reports;
using Argus.Core.Snapshots;
using TunnelEye.App;
using Xunit;

namespace Argus.Core.Tests
{
    public class EvidenceTableTests
    {
        private static Snapshot LargeSource()
        {
            var tree = TestData.LoadTree("hosts-sensitive");
            var hosts = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(JsonValue.Get(tree["modules"], "dns-proxy"), "data"), "hosts"));
            hosts["entries"] = new object[] {
                new Dictionary<string, object> { ["address"] = "203.0.113.50", ["names"] = Enumerable.Range(0, 600).Select(i => new string('a', 60) + i + ".paypal.com").ToArray() },
                new Dictionary<string, object> { ["address"] = "203.0.113.51", ["names"] = new[] { "other.paypal.com" } }
            };
            return Snapshot.Parse(JsonValue.Serialize(tree));
        }

        [Theory]
        [InlineData("ru", "Домен", "Адрес", "Источник", "Технический JSON")]
        [InlineData("en", "Domain", "Address", "Source", "Technical JSON")]
        public void Large_hosts_groups_keep_every_row_sources_and_masked_aliases(string language, string domain, string address, string sourceLabel, string jsonLabel)
        {
            var snapshot = LargeSource();
            var before = JsonValue.Serialize(snapshot.Root);
            var report = Report.Build(snapshot, TestData.Analyze(snapshot), language);
            foreach (var output in new[] { report, report.Masked(new PrivacyMasker(snapshot)) })
            {
                var groups = EvidenceTable.Groups(JsonValue.GetList(output.Root, "checks").Single(c => Equals(JsonValue.Get(c, "id"), "hosts-sensitive"))).ToArray();
                Assert.Equal(2, groups.Length);
                Assert.Equal(600, groups[0].Rows(language).Count());
                Assert.Single(groups[1].Rows(language));
                Assert.Equal(new[] { domain, address, sourceLabel }, groups[0].Headers(language));
                Assert.All(groups[0].Rows(language), row => {
                    Assert.Equal(groups[0].Address, row[1]);
                    Assert.Equal("dns-proxy.hosts.entries[0]", row[2]);
                });
                var html = HtmlReport.Write(output);
                Assert.Contains("<th scope=\"col\">" + domain + "</th>", html);
                Assert.Contains("<summary>" + jsonLabel + "</summary><pre>", html);
                Assert.Contains("overflow-wrap:anywhere", html);
                Assert.Contains("max-height:28rem", html);
                Assert.Contains(groups[0].Rows(language).Last()[0], html);
                Assert.Equal(600, html.Split(new[] { ">dns-proxy.hosts.entries[0]</td>" }, StringSplitOptions.None).Length - 1);
                if (Equals(output.Root["masked"], true))
                {
                    Assert.DoesNotContain("203.0.113.50", html);
                    Assert.DoesNotContain("203.0.113.51", html);
                    Assert.StartsWith("IP-", groups[0].Address);
                    Assert.Contains(groups[0].Address, JsonValue.Serialize(groups[0].Evidence));
                }
            }
            Assert.Equal(before, JsonValue.Serialize(snapshot.Root));
        }

        [Theory]
        [InlineData("ru", "Параметр", "Значение", "Источник", "Да", "Неизвестно")]
        [InlineData("en", "Property", "Value", "Source", "Yes", "Unknown")]
        public void Non_hosts_fields_are_readable_and_html_cells_are_inert(string language, string field, string value, string source, string yes, string unknown)
        {
            var snapshot = TestData.LoadSnapshot("dead-proxy");
            var report = Report.Build(snapshot, TestData.Analyze(snapshot), language);
            var check = JsonValue.AsObject(JsonValue.GetList(report.Root, "checks").First(c => Equals(JsonValue.Get(c, "status"), "found")));
            check["evidence"] = JsonValue.Parse("[{\"values\":{\"name\":\"<img src=x onerror=attack>\",\"elevated\":true,\"futureField\":null,\"servers\":[\"one\",\"two\"]},\"sources\":[\"<script>attack</script>\"]}]");
            var group = EvidenceTable.Groups(check).Single();
            Assert.False(group.IsHosts);
            Assert.Equal(new[] { field, value, source }, group.Headers(language));
            var rows = group.Rows(language).ToArray();
            Assert.Equal(yes, rows[1][1]); Assert.Equal(unknown, rows[2][1]); Assert.Equal("one\ntwo", rows[3][1]);
            var html = HtmlReport.Write(report);
            Assert.DoesNotContain("<img src=x", html); Assert.DoesNotContain("<script>attack", html);
            Assert.Contains("&lt;img", html); Assert.Contains("&lt;script&gt;attack", html);
        }

        [Theory]
        [InlineData("ru")]
        [InlineData("en")]
        public void Native_table_is_lazy_scrollable_wrapped_and_keeps_json_collapsed(string language)
        {
            Exception failure = null;
            var thread = new Thread(() => {
                try
                {
                    var snapshot = LargeSource();
                    var report = Report.Build(snapshot, TestData.Analyze(snapshot), language).Masked(new PrivacyMasker(snapshot));
                    var check = JsonValue.GetList(report.Root, "checks").Single(c => Equals(JsonValue.Get(c, "id"), "hosts-sensitive"));
                    var group = EvidenceTable.Groups(check).First();
                    var view = Assert.IsType<Expander>(EvidenceView.Create(group, language));
                    Assert.False(view.IsExpanded); Assert.Null(view.Content);
                    view.IsExpanded = true;
                    var panel = Assert.IsType<StackPanel>(view.Content);
                    var table = Assert.IsType<DataGrid>(panel.Children[0]);
                    Assert.Equal(600, table.Items.Count); Assert.True(table.IsReadOnly); Assert.True(table.EnableRowVirtualization);
                    Assert.Equal(420, table.MaxHeight); Assert.Equal(3, table.Columns.Count);
                    Assert.Equal(group.Headers(language), table.Columns.Select(c => (string)c.Header));
                    var column = Assert.IsType<DataGridTextColumn>(table.Columns[0]);
                    Assert.Contains(column.ElementStyle.Setters.OfType<Setter>(), s => s.Property == TextBlock.TextWrappingProperty && Equals(s.Value, TextWrapping.Wrap));
                    var technical = Assert.IsType<Expander>(panel.Children[1]);
                    Assert.Equal("EvidenceJson", AutomationProperties.GetAutomationId(technical));
                    Assert.False(technical.IsExpanded); Assert.Null(technical.Content);
                    technical.IsExpanded = true;
                    var text = Assert.IsType<TextBox>(technical.Content);
                    Assert.True(text.IsReadOnly); Assert.DoesNotContain("203.0.113.50", text.Text); Assert.Contains(group.Address, text.Text);
                    view.Measure(new Size(1000, 800)); view.Arrange(new Rect(0, 0, 1000, 800)); view.UpdateLayout();
                    Assert.InRange(table.ActualHeight, 70, 420);
                    view.IsExpanded = false; view.IsExpanded = true;
                    Assert.Same(panel, view.Content);
                }
                catch (Exception e) { failure = e; }
                finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start();
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "Evidence WPF test timed out.");
            if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }
}
