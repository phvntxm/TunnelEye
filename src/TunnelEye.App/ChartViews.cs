// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Argus.Core.Json;
using Argus.Core.Reports;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using OxyPlot.Wpf;

namespace TunnelEye.App
{
    /// <summary>Native, read-only charts of report data; no HTML or script rendering.</summary>
    public static class ChartViews
    {
        private static readonly OxyColor Ink = OxyColor.FromRgb(24, 42, 65);
        private static readonly OxyColor Slate = OxyColor.FromRgb(93, 111, 132);
        private static readonly OxyColor Teal = OxyColor.FromRgb(20, 134, 128);
        private static readonly OxyColor GridLine = OxyColor.FromRgb(229, 235, 242);
        private static readonly Color CardBorder = Color.FromRgb(222, 230, 240);

        public static FrameworkElement Create(Report report, string language)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));
            var culture = CultureInfo.GetCultureInfo(language);
            var stack = new StackPanel { Margin = new Thickness(4) };
            var scroll = new ScrollViewer
            {
                Content = stack,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                PanningMode = PanningMode.VerticalOnly,
            };
            stack.Children.Add(new TextBlock
            {
                Text = ReportText.Get("ChartScope", language),
                TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush(Color.FromRgb(83, 101, 123)),
                Margin = new Thickness(4, 4, 4, 16),
                FontSize = 13,
            });

            var summary = JsonValue.Get(report.Root, "summary");
            var counts = JsonValue.AsObject(JsonValue.Get(summary, "counts"));
            var levels = new[] { "critical", "important", "advice", "info" };
            var colors = new[]
            {
                OxyColor.FromRgb(192, 53, 71), OxyColor.FromRgb(185, 126, 15),
                Teal, OxyColor.FromRgb(93, 111, 132),
            };
            var severity = new List<ChartPoint>();
            for (var i = 0; i < levels.Length; i++)
            {
                object value;
                double number;
                if (counts != null && counts.TryGetValue(levels[i], out value) && TryNumber(value, out number))
                    severity.Add(new ChartPoint(ReportText.Get("Level_" + levels[i], language), number, colors[i]));
            }
            stack.Children.Add(Card(ReportText.Get("Counts", language), severity, culture, language, true));

            var charts = JsonValue.AsObject(JsonValue.Get(report.Root, "charts"));
            foreach (var key in new[] { "Latency", "Losses", "WifiChannels", "WifiUtilization", "DnsLatency", "EventTimeline" })
            {
                var points = new List<ChartPoint>();
                object raw;
                if (charts != null && charts.TryGetValue(key, out raw))
                {
                    foreach (var item in JsonValue.AsList(raw) ?? new object[0])
                    {
                        double number;
                        if (!TryNumber(JsonValue.Get(item, "value"), out number)) continue;
                        points.Add(new ChartPoint(JsonValue.AsString(JsonValue.Get(item, "label")) ?? string.Empty, number, Teal));
                    }
                }
                stack.Children.Add(Card(ReportText.Get(key, language), points, culture, language, key == "EventTimeline"));
            }

            // Wheel movement scrolls the page instead of unexpectedly zooming a chart.
            scroll.PreviewMouseWheel += (sender, args) =>
            {
                scroll.ScrollToVerticalOffset(scroll.VerticalOffset - args.Delta);
                args.Handled = true;
            };
            AutomationProperties.SetName(scroll, ReportText.Get("Charts", language));
            return scroll;
        }

        private static FrameworkElement Card(string title, IList<ChartPoint> points, CultureInfo culture, string language, bool integerTicks = false)
        {
            FrameworkElement content;
            if (points.Count == 0)
            {
                var empty = new StackPanel { Margin = new Thickness(14) };
                empty.Children.Add(new TextBlock
                {
                    Text = title,
                    FontSize = 17,
                    FontWeight = System.Windows.FontWeights.SemiBold,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = new SolidColorBrush(Color.FromRgb(24, 42, 65)),
                });
                empty.Children.Add(new TextBlock
                {
                    Text = ReportText.Get("NoData", language),
                    Foreground = new SolidColorBrush(Color.FromRgb(93, 111, 132)),
                    Margin = new Thickness(0, 10, 0, 2),
                });
                content = empty;
            }
            else
            {
                var model = new PlotModel
                {
                    Title = title,
                    TitleFontSize = 17,
                    TitleFontWeight = 500,
                    DefaultFont = "Segoe UI",
                    DefaultFontSize = 12,
                    TextColor = Ink,
                    Background = OxyColors.White,
                    PlotAreaBorderColor = OxyColors.Transparent,
                    Culture = culture,
                    IsLegendVisible = false,
                };
                var categories = new CategoryAxis
                {
                    Position = AxisPosition.Left,
                    StartPosition = 1,
                    EndPosition = 0,
                    AxislineStyle = LineStyle.None,
                    TickStyle = TickStyle.None,
                    TextColor = Slate,
                    FontSize = 11,
                    IsPanEnabled = false,
                    IsZoomEnabled = false,
                    GapWidth = 0.7,
                };
                foreach (var point in points) categories.Labels.Add(point.Label + " · " + point.Value.ToString("0.##", culture));
                var values = new LinearAxis
                {
                    Position = AxisPosition.Bottom,
                    Minimum = 0,
                    AbsoluteMinimum = 0,
                    Maximum = points.All(p => p.Value == 0) ? 1 : double.NaN,
                    MinimumMajorStep = integerTicks ? 1 : 0,
                    MinimumPadding = 0,
                    MaximumPadding = 0.16,
                    MajorGridlineStyle = LineStyle.Solid,
                    MajorGridlineColor = GridLine,
                    MinorGridlineStyle = LineStyle.None,
                    AxislineStyle = LineStyle.None,
                    TickStyle = TickStyle.None,
                    TextColor = Slate,
                    StringFormat = "0.##",
                    IsPanEnabled = false,
                    IsZoomEnabled = false,
                };
                var series = new BarSeries
                {
                    FillColor = Teal,
                    StrokeThickness = 0,
                    LabelFormatString = "",
                    LabelMargin = 6,
                    TrackerFormatString = "{1}: {2:0.##}",
                };
                foreach (var point in points) series.Items.Add(new BarItem(point.Value) { Color = point.Color });
                model.Axes.Add(categories);
                model.Axes.Add(values);
                model.Series.Add(series);
                var plot = new PlotView
                {
                    Model = model,
                    Height = Math.Max(230, points.Count * 32 + 100),
                    Margin = new Thickness(10),
                    Focusable = true,
                };
                AutomationProperties.SetName(plot, title);
                content = plot;
            }
            return new Border
            {
                Child = content,
                Background = Brushes.White,
                BorderBrush = new SolidColorBrush(CardBorder),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Margin = new Thickness(0, 0, 0, 16),
            };
        }

        private static bool TryNumber(object value, out double number)
        {
            number = 0;
            if (!JsonValue.IsNumber(value)) return false;
            number = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            return !double.IsNaN(number) && !double.IsInfinity(number) && number >= 0;
        }

        private sealed class ChartPoint
        {
            internal ChartPoint(string label, double value, OxyColor color) { Label = label; Value = value; Color = color; }
            internal string Label { get; }
            internal double Value { get; }
            internal OxyColor Color { get; }
        }
    }
}
