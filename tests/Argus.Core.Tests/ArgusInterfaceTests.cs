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
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Argus.Core.Json;
using Argus.Core.Reports;
using TunnelEye.App;
using Xunit;

namespace Argus.Core.Tests
{
    public class ArgusInterfaceTests
    {
        [Theory]
        [InlineData("ru", "Прогресс пока неизвестен", "DNS и прокси")]
        [InlineData("en", "Progress not yet known", "DNS and proxy")]
        public void Only_events_advance_progress_and_module_failures_do_not_abort_others(string language, string unknown, string module)
        {
            var state = new CollectionDisplay();
            Assert.Equal(unknown, state.Count(language)); Assert.Null(state.Total); Assert.False(state.CanAnimate);
            state.Accept(new CollectionProgress(0, 13, null, "notElevated"));
            Assert.False(state.Elevated); Assert.Null(state.Total);
            state.Accept(new CollectionProgress(0, 13, null, "start", false));
            Assert.Equal(13, state.Total); Assert.True(state.CanAnimate);
            state.Accept(new CollectionProgress(3, 13, "dns-proxy", "running"));
            Assert.Equal(3, state.Done); Assert.Equal(0, state.ActiveEye); Assert.Contains(module, state.Current(language));
            state.Accept(new CollectionProgress(4, 13, "dns-proxy", "failed"));
            Assert.True(state.ModuleFailed); Assert.False(state.Failed); Assert.True(state.CanAnimate); Assert.Equal(1, state.ActiveEye);
            state.Accept(new CollectionProgress(4, 13, "dns-proxy", "failed"));
            Assert.Equal(1, state.ActiveEye);
            state.Accept(new CollectionProgress(4, 13, "vpn", "running"));
            Assert.False(state.ModuleFailed);
            state.Accept(new CollectionProgress(1, 2, "hardware", "running"));
            Assert.Equal(13, state.Total); Assert.Equal("vpn", state.Module);
            state.Accept(new CollectionProgress(0, 0, null, "slow"));
            Assert.True(state.Slow); Assert.Equal("vpn", state.Module); Assert.Equal(4, state.Done);
            state.Analyze(); Assert.False(state.CanAnimate);
            state.Accept(new CollectionProgress(13, 13, null, "end"));
            Assert.Equal(4, state.Done); // Late queued events cannot rewrite analysis state.
        }

        [Fact]
        public void Terminal_and_unknown_states_keep_honest_counts()
        {
            var state = new CollectionDisplay();
            state.Accept(new CollectionProgress(5, 0, "dns-proxy", "running"));
            Assert.Null(state.Total); Assert.Equal(0, state.Done);
            state.Accept(new CollectionProgress(2, 13, "dns-proxy", "running"));
            state.Fail(); Assert.False(state.CanAnimate); Assert.Contains("DNS", state.Current("en"));
            state.Accept(new CollectionProgress(13, 13, null, "end")); Assert.Equal(2, state.Done);
            var complete = new CollectionDisplay();
            complete.Accept(new CollectionProgress(13, 13, null, "end"));
            Assert.True(complete.Ended); Assert.False(complete.CanAnimate); Assert.Equal(13, complete.Done);
        }

        [Fact]
        public void Native_animation_obeys_system_preference_and_releases_timer_on_unload()
        {
            Sta(async () => {
                var allowed = true;
                var eyes = new ArgusEyes(() => allowed) { IsActive = true };
                var window = Host(eyes); window.Show(); window.UpdateLayout();
                try
                {
                    Assert.True(eyes.AnimationsEnabled); Assert.True(eyes.IsAnimating);
                    eyes.AnimationsEnabled = false; Assert.False(eyes.IsAnimating);
                    eyes.AnimationsEnabled = true; Assert.True(eyes.IsAnimating);
                    allowed = false; eyes.RefreshMotionPreference(); Assert.False(eyes.IsAnimating);
                    allowed = true; eyes.RefreshMotionPreference(); Assert.True(eyes.IsAnimating);
                    window.Content = null; Assert.False(eyes.IsAnimating);
                    window.Content = eyes; window.UpdateLayout(); Assert.True(eyes.IsAnimating);
                    eyes.IsActive = false; Assert.False(eyes.IsAnimating);
                    eyes.IsActive = true; eyes.Finish(); Assert.False(eyes.IsAnimating);
                    eyes.Dispose(); Assert.False(eyes.IsAnimating);
                    eyes.IsActive = true; Assert.False(eyes.IsAnimating);
                    await Task.Yield();
                }
                finally { eyes.Dispose(); window.Close(); }
            });
        }

        [Theory]
        [InlineData("ru")]
        [InlineData("en")]
        public void Static_diagnostic_view_keeps_current_module_and_measured_progress(string language)
        {
            Sta(async () => {
                var state = new CollectionDisplay();
                state.Accept(new CollectionProgress(3, 13, "dns-proxy", "running", false));
                var view = new DiagnosisView(state, language, false);
                var window = Host(view); AppTheme.Apply(window); window.Show(); window.UpdateLayout();
                try
                {
                    var values = Logical(view).OfType<TextBlock>().ToArray();
                    Assert.Equal(state.Current(language), values.Single(t => AutomationProperties.GetAutomationId(t) == "CurrentModule").Text);
                    Assert.Equal(state.Count(language), values.Single(t => AutomationProperties.GetAutomationId(t) == "CompletedModules").Text);
                    var progress = Logical(view).OfType<ProgressBar>().Single();
                    Assert.Equal(3, progress.Value); Assert.Equal(13, progress.Maximum); Assert.False(progress.IsIndeterminate);
                    Assert.False(view.Eyes.IsAnimating);
                    var current = values.Single(t => AutomationProperties.GetAutomationId(t) == "CurrentModule");
                    var position = current.TranslatePoint(new Point(), view);
                    Assert.InRange(position.Y + current.ActualHeight, 0, view.ActualHeight);
                    Assert.Same(AppTheme.Surface, view.Background);
                    state.Fail(); view.Update(); Assert.False(view.Eyes.IsAnimating);
                    Assert.Contains(ReportText.Get("Module_dns-proxy", language), current.Text);
                    await Task.Yield();
                }
                finally { view.Dispose(); window.Close(); }
            });
        }

        [Fact]
        public void Real_window_handles_restart_failure_and_late_events_without_uac()
        {
            Sta(async () => {
                var completions = new List<TaskCompletionSource<CollectionRunResult>>();
                var notifications = new List<IProgress<CollectionProgress>>();
                var path = Path.Combine(Path.GetTempPath(), "TunnelEye-design-" + Guid.NewGuid().ToString("N") + ".json");
                File.WriteAllText(path, JsonValue.Serialize(TestData.LoadTree("clean")));
                var window = new MainWindow(null, (external, events) => {
                    Assert.False(external); notifications.Add(events);
                    var completion = new TaskCompletionSource<CollectionRunResult>(); completions.Add(completion); return completion.Task;
                });
                window.ShowInTaskbar = false; window.Opacity = 0; window.WindowStartupLocation = WindowStartupLocation.Manual; window.Left = -20000; window.Top = -20000;
                window.Show();
                try
                {
                    var first = window.DiagnoseAsync();
                    Assert.True(Logical(window).OfType<CheckBox>().Single(c => AutomationProperties.GetAutomationId(c) == "EnableAnimations").IsChecked);
                    Assert.Contains(AppStrings.Get("AwaitingCollector", "ru"), Logical(window).OfType<TextBlock>().Single(t => AutomationProperties.GetAutomationId(t) == "CurrentModule").Text);
                    notifications[0].Report(new CollectionProgress(3, 13, "dns-proxy", "running", false));
                    await Dispatcher.Yield(DispatcherPriority.Background);
                    Assert.Contains("DNS", Logical(window).OfType<TextBlock>().Single(t => AutomationProperties.GetAutomationId(t) == "CurrentModule").Text);
                    completions[0].SetException(new CollectionRunException(CollectionFailure.ProcessFailed)); await first;
                    Assert.DoesNotContain(Logical(window).OfType<ArgusEyes>(), e => e.IsAnimating);
                    Assert.Contains(AppStrings.Get("CollectionFailureNote", "ru"), Logical(window).OfType<TextBlock>().Select(t => t.Text));
                    var second = window.DiagnoseAsync();
                    notifications[0].Report(new CollectionProgress(12, 13, "hardware", "running"));
                    await Dispatcher.Yield(DispatcherPriority.Background);
                    Assert.Equal(AppStrings.Get("UnknownProgress", "ru"), Logical(window).OfType<TextBlock>().Single(t => AutomationProperties.GetAutomationId(t) == "CompletedModules").Text);
                    notifications[1].Report(new CollectionProgress(0, 13, null, "start", true));
                    await Dispatcher.Yield(DispatcherPriority.Background);
                    completions[1].SetResult(new CollectionRunResult(path, true)); await second;
                    Assert.Empty(Logical(window).OfType<ArgusEyes>());
                    Assert.Single(Logical(window).OfType<TextBlock>(), t => AutomationProperties.GetAutomationId(t) == "CollectionMode");
                    Assert.Same(AppTheme.Text, Logical(window).OfType<TextBlock>().Single(t => AutomationProperties.GetAutomationId(t) == "CollectionMode").Foreground);
                }
                finally { window.Close(); File.Delete(path); }
            });
        }

        [Fact]
        public void Original_icon_has_small_raster_sizes_and_html_has_print_palette()
        {
            Sta(async () => {
                foreach (var size in new[] { 16, 32, 48 })
                {
                    var icon = Assert.IsType<RenderTargetBitmap>(AppTheme.Icon(size));
                    Assert.Equal(size, icon.PixelWidth); Assert.True(icon.IsFrozen);
                }
                await Task.Yield();
            });
            var snapshot = TestData.LoadSnapshot("hosts-sensitive");
            var html = HtmlReport.Write(Report.Build(snapshot, TestData.Analyze(snapshot)));
            Assert.Contains("background:#202123", html); Assert.Contains("@media print", html);
            Assert.Contains("max-height:none;overflow:visible", html);
            Assert.DoesNotContain("<script", html);
        }

        private static Window Host(UIElement element) => new Window { Content = element, Width = 900, Height = 500, ShowInTaskbar = false, Opacity = 0,
            WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Top = -20000 };
        private static IEnumerable<DependencyObject> Logical(object node)
        {
            if (!(node is DependencyObject item)) yield break;
            yield return item;
            foreach (var child in LogicalTreeHelper.GetChildren(item)) foreach (var descendant in Logical(child)) yield return descendant;
        }
        private static void Sta(Func<Task> action)
        {
            Exception error = null;
            var thread = new Thread(() => {
                SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
                Dispatcher.CurrentDispatcher.BeginInvoke(new Action(async () => {
                    try { await action(); } catch (Exception e) { error = e; }
                    finally { Dispatcher.CurrentDispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
                }));
                Dispatcher.Run();
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start();
            Assert.True(thread.Join(TimeSpan.FromSeconds(35)), "Argus UI test timed out.");
            if (error != null) ExceptionDispatchInfo.Capture(error).Throw();
        }
    }
}
