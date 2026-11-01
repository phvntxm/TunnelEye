// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using System.Xml;
using Argus.Core.Json;
using Argus.Core.Reports;
using Argus.Core.Snapshots;
using TunnelEye.App;
using Xunit;

namespace Argus.Core.Tests
{
    public class BuiltInVpnViewTests
    {
        [Theory]
        [InlineData("ru", "Встроенные VPN Windows", "Имя профиля", "Состояние", "Сервер", "Тип туннеля", "Раздельное туннелирование", "Подключено", "Да")]
        [InlineData("en", "Built-in Windows VPN", "Profile name", "Status", "Server", "Tunnel type", "Split tunneling", "Connected", "Yes")]
        public void Connected_windows_profile_is_present_in_the_real_table_without_third_party_clients(
            string language, string title, string name, string status, string server, string tunnel, string split, string connected, string yes)
        {
            RunSta(() =>
            {
                var report = ReportWithProfiles(@"[{""name"":""Example Windows VPN"",""connectionStatus"":""Connected"",""serverAddress"":""vpn.example.invalid"",""tunnelType"":""Ikev2"",""splitTunneling"":true,""rememberSignIn"":false}]");
                Assert.Empty(JsonValue.GetList(JsonValue.Get(report.Root["sections"], "vpn"), "clients"));
                var view = Layout(BuiltInVpnView.Create(report, language));
                Assert.Equal(title, AutomationProperties.GetName(view));
                Assert.Contains(title, Descendants(view).OfType<TextBlock>().Select(t => t.Text));
                var table = Descendants(view).OfType<Grid>().Single(g => AutomationProperties.GetAutomationId(g) == "BuiltInVpnProfiles");
                var values = Descendants(table).OfType<TextBlock>().Select(t => t.Text).ToArray();
                Assert.Equal(2, table.RowDefinitions.Count);
                Assert.Equal(5, table.ColumnDefinitions.Count);
                Assert.Equal(new[] { name, status, server, tunnel, split, "Example Windows VPN", connected, "vpn.example.invalid", "IKEv2", yes }, values);
                var details = Descendants(view).OfType<Expander>().Single(e => AutomationProperties.GetAutomationId(e) == "BuiltInVpnDetails");
                var technical = Assert.IsType<TextBox>(details.Content);
                Assert.True(technical.IsReadOnly);
                Assert.Contains("rememberSignIn", technical.Text);
                Assert.Contains("Example Windows VPN", technical.Text);
            });
        }

        [Theory]
        [InlineData("ru", "Встроенные VPN-профили не найдены.", "Данные встроенных VPN-профилей не собраны.")]
        [InlineData("en", "No built-in VPN profiles found.", "Built-in VPN profile data was not collected.")]
        public void Empty_profile_list_is_distinct_from_unavailable_profile_data(string language, string empty, string unavailable)
        {
            RunSta(() =>
            {
                var emptyView = Layout(BuiltInVpnView.Create(ReportWithProfiles("[]"), language));
                var unavailableView = Layout(BuiltInVpnView.Create(ReportWithProfiles("null"), language));
                Assert.Contains(empty, Descendants(emptyView).OfType<TextBlock>().Select(t => t.Text));
                Assert.Contains(unavailable, Descendants(unavailableView).OfType<TextBlock>().Select(t => t.Text));
            });
        }

        [Fact]
        public void Vpn_resource_sets_have_matching_nonempty_keys()
        {
            var sets = new List<HashSet<string>>();
            foreach (var suffix in new[] { "", ".en" })
            {
                var document = new XmlDocument();
                document.Load(Path.Combine(TestData.RepoRoot, "src", "TunnelEye.App", "VpnStrings" + suffix + ".resx"));
                var keys = new HashSet<string>();
                foreach (XmlElement node in document.SelectNodes("/root/data"))
                {
                    Assert.True(keys.Add(node.GetAttribute("name")));
                    Assert.False(string.IsNullOrWhiteSpace(node["value"].InnerText));
                }
                sets.Add(keys);
            }
            Assert.True(sets[0].SetEquals(sets[1]));
        }

        private static Report ReportWithProfiles(string profiles)
        {
            var tree = TestData.LoadTree("clean");
            var vpn = JsonValue.AsObject(JsonValue.Get(JsonValue.Get(tree["modules"], "vpn"), "data"));
            vpn["clients"] = new object[0];
            vpn["builtIn"] = JsonValue.Parse("{\"profiles\":" + profiles + ",\"services\":[]}");
            var snapshot = Snapshot.Parse(JsonValue.Serialize(tree));
            return Report.Build(snapshot, TestData.Analyze(snapshot));
        }

        private static FrameworkElement Layout(FrameworkElement view)
        {
            view.Measure(new Size(1100, 800));
            view.Arrange(new Rect(0, 0, 1100, view.DesiredSize.Height));
            view.UpdateLayout();
            return view;
        }

        private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
        {
            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                yield return child;
                foreach (var descendant in Descendants(child)) yield return descendant;
            }
        }

        private static void RunSta(Action action)
        {
            Exception failure = null;
            var thread = new Thread(() =>
            {
                try { action(); }
                catch (Exception e) { failure = e; }
                finally { Dispatcher.CurrentDispatcher.InvokeShutdown(); }
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            Assert.True(thread.Join(TimeSpan.FromSeconds(20)), "WPF test did not complete.");
            if (failure != null) ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }
}
