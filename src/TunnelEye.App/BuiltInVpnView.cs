// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.Resources;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Argus.Core.Json;
using Argus.Core.Reports;

namespace TunnelEye.App
{
    /// <summary>Built-in Windows VPN profiles, separate from signature-matched clients.</summary>
    public static class BuiltInVpnView
    {
        private static readonly ResourceManager Strings = new ResourceManager("TunnelEye.App.VpnStrings", typeof(BuiltInVpnView).Assembly);

        public static FrameworkElement Create(Report report, string language)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));
            var culture = CultureInfo.GetCultureInfo(language);
            Func<string, string> text = key => Strings.GetString(key, culture) ?? key;
            var vpn = JsonValue.Get(report.Root["sections"], "vpn");
            var builtIn = JsonValue.Get(vpn, "builtIn");
            var profiles = JsonValue.AsList(JsonValue.Get(builtIn, "profiles"));
            var content = new StackPanel();
            content.Children.Add(Label(text("Title"), 20, true));
            if (profiles == null)
                content.Children.Add(Label(text("Unavailable")));
            else if (profiles.Count == 0)
                content.Children.Add(Label(text("Empty")));
            else
            {
                var table = new Grid { Margin = new Thickness(0, 3, 0, 12) };
                AutomationProperties.SetAutomationId(table, "BuiltInVpnProfiles");
                AutomationProperties.SetName(table, text("Title"));
                var headers = new[] { "Name", "ConnectionStatus", "Server", "TunnelType", "SplitTunneling" };
                var fields = new[] { "name", "connectionStatus", "serverAddress", "tunnelType", "splitTunneling" };
                foreach (var header in headers)
                    table.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star), MinWidth = 105 });
                table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                for (var column = 0; column < headers.Length; column++)
                    Cell(table, text(headers[column]), 0, column, true);
                for (var row = 0; row < profiles.Count; row++)
                {
                    table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                    for (var column = 0; column < fields.Length; column++)
                    {
                        var value = JsonValue.Get(profiles[row], fields[column]);
                        string display;
                        if (value == null) display = text("Unknown");
                        else if (value is bool) display = text((bool)value ? "Yes" : "No");
                        else
                        {
                            display = Convert.ToString(value, culture);
                            if (fields[column] == "connectionStatus" || fields[column] == "tunnelType")
                                display = Strings.GetString(fields[column] + "_" + display, culture) ?? display;
                        }
                        Cell(table, display, row + 1, column, false);
                    }
                }
                content.Children.Add(table);
            }

            var details = new Expander
            {
                Header = text("TechnicalDetails"),
                Margin = new Thickness(0, 8, 0, 0),
                Content = new TextBox
                {
                    Text = JsonValue.Serialize(builtIn),
                    IsReadOnly = true,
                    TextWrapping = TextWrapping.Wrap,
                    MaxHeight = 300,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    Padding = new Thickness(10),
                },
            };
            AutomationProperties.SetAutomationId(details, "BuiltInVpnDetails");
            content.Children.Add(details);
            var card = new Border
            {
                Background = AppTheme.Surface,
                BorderBrush = AppTheme.Line,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(22),
                Margin = new Thickness(0, 0, 0, 14),
                Child = content,
            };
            AutomationProperties.SetAutomationId(card, "BuiltInVpn");
            AutomationProperties.SetName(card, text("Title"));
            return card;
        }

        private static TextBlock Label(string value, double size = 14, bool bold = false)
        {
            return new TextBlock
            {
                Text = value ?? string.Empty, Foreground = AppTheme.Text,
                TextWrapping = TextWrapping.Wrap,
                FontSize = size,
                FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
                Margin = new Thickness(0, 0, 0, 8),
            };
        }

        private static void Cell(Grid table, string value, int row, int column, bool header)
        {
            var cell = new Border
            {
                Padding = new Thickness(8, 7, 10, 7),
                BorderBrush = AppTheme.Line,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Background = header ? AppTheme.Raised : Brushes.Transparent,
                Child = new TextBlock
                {
                    Text = value, Foreground = AppTheme.Text,
                    TextWrapping = TextWrapping.Wrap,
                    FontWeight = header ? FontWeights.SemiBold : FontWeights.Normal,
                },
            };
            Grid.SetRow(cell, row);
            Grid.SetColumn(cell, column);
            table.Children.Add(cell);
        }
    }
}
