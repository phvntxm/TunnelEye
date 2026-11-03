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
using System.Windows.Threading;
using Argus.Core.Json;
using Argus.Core.Reports;
using TunnelEye.App;
using Xunit;

namespace Argus.Core.Tests
{
    // WPF's shared package resource loader is not safe across concurrent STA
    // dispatchers. The application itself has a single UI dispatcher.
    [CollectionDefinition("WPF resources", DisableParallelization = true)]
    public class WpfResourceCollection { }

    [Collection("WPF resources")]
    public class ExplanationViewTests
    {
        [Theory]
        [InlineData("vpn-expected", "expectedBehavior")]
        [InlineData("vpn-conflict", "possibleCause")]
        [InlineData("dead-proxy", "confirmedConfigurationProblem")]
        public void Wpf_first_screen_shows_status_mechanism_action_and_limit_before_expansion(string fixture, string assessment)
        {
            Exception error = null;
            var thread = new Thread(() => {
                var dispatcher = Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
                dispatcher.BeginInvoke(new Action(async () => {
                    var path = Path.Combine(Path.GetTempPath(), "TunnelEye-explanation-" + Guid.NewGuid().ToString("N") + ".json");
                    var window = new MainWindow();
                    try
                    {
                        File.WriteAllText(path, JsonValue.Serialize(TestData.LoadSnapshot(fixture).Root));
                        await window.OpenSnapshotAsync(path);
                        foreach (var language in new[] { "ru", "en" })
                        {
                            var header = (Grid)((DockPanel)window.Content).Children[0];
                            ((ComboBox)header.Children[1]).SelectedIndex = language == "ru" ? 0 : 1;
                            var cards = Descendants(window.Content).OfType<StackPanel>().Where(p => AutomationProperties.GetAutomationId(p) == "ReportExplanation");
                            var card = cards.First(p => p.Children.OfType<TextBlock>().Any(t => t.Text == ReportText.Get("ExAssessment_" + assessment, language)));
                            var firstScreen = card.Children.OfType<TextBlock>().Select(t => t.Text).ToArray();
                            foreach (var key in new[] { "ExMechanism", "ExAction", "ExLimit" })
                                Assert.Contains(firstScreen, t => t.StartsWith(ReportText.Get(key, language) + ": ", StringComparison.Ordinal));
                            var details = Assert.Single(card.Children.OfType<Expander>());
                            Assert.False(details.IsExpanded);
                            var grid = Assert.Single(Descendants(details.Content).OfType<DataGrid>());
                            Assert.Equal(4, grid.Columns.Count); Assert.True(grid.IsReadOnly);
                            Assert.NotEmpty(grid.Items);
                            var json = Assert.Single(Descendants(details.Content).OfType<TextBox>());
                            Assert.True(json.IsReadOnly); Assert.Contains("evidenceRefs", json.Text);
                        }
                    }
                    catch (Exception e) { error = e; }
                    finally { window.Close(); File.Delete(path); dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
                }));
                Dispatcher.Run();
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start();
            Assert.True(thread.Join(TimeSpan.FromSeconds(35)), "Explanation view timed out.");
            if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
        }

        private static IEnumerable<DependencyObject> Descendants(object node)
        {
            if (!(node is DependencyObject dependency)) yield break;
            yield return dependency;
            foreach (var child in LogicalTreeHelper.GetChildren(dependency))
                foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }
}
