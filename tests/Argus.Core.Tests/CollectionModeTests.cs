// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
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
    public class CollectionModeTests
    {
        private static Snapshot Source(bool? elevated)
        {
            var tree = TestData.LoadTree("clean");
            var host = JsonValue.AsObject(tree["host"]);
            if (elevated.HasValue) host["elevated"] = elevated.Value; else host.Remove("elevated");
            return Snapshot.Parse(JsonValue.Serialize(tree));
        }
        [Theory]
        [InlineData(true, "CollectionModeElevated")]
        [InlineData(false, "CollectionModeLimited")]
        [InlineData(null, "CollectionModeUnknown")]
        public void Permissions_survive_report_exports(bool? elevated, string key)
        {
            var source = Source(elevated);
            foreach (var language in new[] { "ru", "en" })
            {
                var report = Report.Build(source, TestData.Analyze(source), language);
                foreach (var output in new[] { report, report.Masked(new PrivacyMasker(source)) })
                {
                    Assert.Equal(elevated, output.CollectionElevated);
                    var json = JsonValue.Parse(output.Json());
                    Assert.Equal(elevated, JsonValue.AsBool(JsonValue.Get(JsonValue.Get(json, "collection"), "elevated")));
                    var label = ReportText.Get(key, language);
                    Assert.NotEqual(key, label);
                    Assert.Contains(label, HtmlReport.Write(output));
                }
            }
        }
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        [InlineData(null)]
        public void Opening_a_saved_snapshot_shows_a_persistent_native_badge(bool? elevated)
        {
            Exception error = null;
            var thread = new Thread(() => {
                var dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
                Func<Task> test = async () => {
                    var path = Path.Combine(Path.GetTempPath(), "TunnelEye-mode-" + Guid.NewGuid().ToString("N") + ".json");
                    var window = new MainWindow();
                    try
                    {
                        File.WriteAllText(path, JsonValue.Serialize(Source(elevated).Root));
                        await window.OpenSnapshotAsync(path);
                        foreach (var language in new[] { "ru", "en" })
                        {
                            var header = (Grid)((DockPanel)window.Content).Children[0];
                            ((ComboBox)header.Children[1]).SelectedIndex = language == "ru" ? 0 : 1;
                            var badge = Descendants(window.Content).OfType<TextBlock>().Single(t => AutomationProperties.GetAutomationId(t) == "CollectionMode");
                            var key = elevated == true ? "CollectionModeElevated" : elevated == false ? "CollectionModeLimited" : "CollectionModeUnknown";
                            Assert.Equal(ReportText.Get(key, language), badge.Text);
                        }
                    }
                    finally { window.Close(); File.Delete(path); }
                };
                dispatcher.BeginInvoke(new Action(async () => {
                    try { await test(); } catch (Exception e) { error = e; }
                    finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
                }));
                Dispatcher.Run();
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start();
            Assert.True(thread.Join(TimeSpan.FromSeconds(30)), "Saved-snapshot WPF test timed out.");
            if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
        }
        private static IEnumerable<DependencyObject> Descendants(object node)
        {
            var dependency = node as DependencyObject;
            if (dependency == null) yield break;
            yield return dependency;
            foreach (var child in LogicalTreeHelper.GetChildren(dependency))
                foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }
}
