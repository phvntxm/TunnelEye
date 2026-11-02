// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0
using System;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;

namespace TunnelEye.App
{
    public sealed class DiagnosisView : Border, IDisposable
    {
        private readonly CollectionDisplay state;
        private readonly string language;
        private readonly TextBlock current, count, mode, note;
        private readonly ProgressBar progress;
        public ArgusEyes Eyes { get; }
        public DiagnosisView(CollectionDisplay display, string lang, bool animations)
        {
            state = display ?? throw new ArgumentNullException(nameof(display)); language = lang;
            Background = AppTheme.Surface; CornerRadius = new CornerRadius(12); Padding = new Thickness(26);
            var panel = new Grid();
            panel.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star), MaxHeight = 280 });
            for (var i = 0; i < 5; i++) panel.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Eyes = new ArgusEyes { AnimationsEnabled = animations, Margin = new Thickness(0, 0, 0, 20) };
            AutomationProperties.SetName(Eyes, AppStrings.Get("ArgusAnimation", language));
            panel.Children.Add(Eyes);
            mode = Label(12); mode.Foreground = AppTheme.Muted; Grid.SetRow(mode, 1); panel.Children.Add(mode);
            current = Label(24); current.FontWeight = FontWeights.SemiBold; Grid.SetRow(current, 2); panel.Children.Add(current);
            count = Label(14); Grid.SetRow(count, 3); panel.Children.Add(count);
            progress = new ProgressBar { Height = 5, Minimum = 0, Foreground = AppTheme.Accent, Background = AppTheme.Raised, Margin = new Thickness(0, 4, 0, 12) };
            Grid.SetRow(progress, 4); panel.Children.Add(progress);
            note = Label(12); note.Foreground = AppTheme.Muted; Grid.SetRow(note, 5); panel.Children.Add(note);
            AutomationProperties.SetAutomationId(current, "CurrentModule");
            AutomationProperties.SetAutomationId(count, "CompletedModules");
            AutomationProperties.SetAutomationId(mode, "CollectionRights");
            AutomationProperties.SetAutomationId(progress, "MeasuredProgress");
            AutomationProperties.SetLiveSetting(current, AutomationLiveSetting.Polite);
            Child = panel; Update();
        }
        private static TextBlock Label(double size) => new TextBlock { Foreground = AppTheme.Text, FontSize = size, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) };
        public void Update()
        {
            current.Text = state.Current(language); count.Text = state.Count(language); mode.Text = state.Mode(language); note.Text = state.Note(language);
            progress.Maximum = Math.Max(1, state.Total ?? 1); progress.Value = state.Done;
            // Unknown means unknown: never fill a measured bar from a decorative clock.
            progress.IsIndeterminate = false;
            progress.Foreground = state.Failed ? AppTheme.Critical : AppTheme.Accent;
            Eyes.ActiveEye = state.ActiveEye; Eyes.IsActive = state.CanAnimate;
        }
        public void Dispose() => Eyes.Dispose();
    }
}
