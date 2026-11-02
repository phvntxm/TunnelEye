// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.Linq;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Argus.Core.Json;
using Argus.Core.Reports;

namespace TunnelEye.App
{
    public static class EvidenceView
    {
        public static FrameworkElement Create(EvidenceTable group, string language)
        {
            var expander = new Expander { Header = group.Title(language), Margin = new Thickness(0, 6, 0, 6) };
            AutomationProperties.SetAutomationId(expander, "EvidenceGroup");
            // Large groups allocate controls only when the owner asks to see them.
            expander.Expanded += (sender, args) =>
            {
                if (args.OriginalSource != expander || expander.Content != null) return;
                var panel = new StackPanel();
                var table = new DataGrid
                {
                    AutoGenerateColumns = false, IsReadOnly = true, CanUserAddRows = false, CanUserDeleteRows = false,
                    CanUserReorderColumns = false, HeadersVisibility = DataGridHeadersVisibility.Column,
                    GridLinesVisibility = DataGridGridLinesVisibility.Horizontal, RowHeaderWidth = 0,
                    MinHeight = 70, MaxHeight = 420, EnableRowVirtualization = true, EnableColumnVirtualization = true,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    ItemsSource = group.Rows(language).ToArray(),
                };
                AutomationProperties.SetAutomationId(table, "EvidenceTable");
                var wrap = new Style(typeof(TextBlock));
                wrap.Setters.Add(new Setter(TextBlock.TextWrappingProperty, TextWrapping.Wrap));
                wrap.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(8, 6, 8, 6)));
                var headers = group.Headers(language);
                for (var i = 0; i < headers.Length; i++)
                    table.Columns.Add(new DataGridTextColumn { Header = headers[i], Binding = new Binding("[" + i + "]"),
                        Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 110, ElementStyle = wrap });
                panel.Children.Add(table);
                var technical = new Expander { Header = ReportText.Get("EvidenceJson", language), Margin = new Thickness(0, 8, 0, 8) };
                AutomationProperties.SetAutomationId(technical, "EvidenceJson");
                technical.Expanded += (s, e) =>
                {
                    if (technical.Content == null) technical.Content = new TextBox { Text = JsonValue.Serialize(group.Evidence),
                        IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 300,
                        VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas"), FontSize = 12 };
                };
                panel.Children.Add(technical);
                expander.Content = panel;
            };
            return expander;
        }
    }
}
