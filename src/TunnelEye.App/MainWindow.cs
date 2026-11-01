// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Json;
using Argus.Core.Reports;
using Argus.Core.Rules;
using Argus.Core.Snapshots;
using Microsoft.Win32;

namespace TunnelEye.App
{
    public sealed class MainWindow : Window
    {
        private string language = "ru";
        private Snapshot snapshot;
        private string sourcePath;
        private AnalysisResult analysis;
        private Report report;
        private bool busy;
        private string statusKey = "Ready";
        private CheckBox consent, mask;
        private TextBlock status;
        private ProgressBar progress;
        private readonly List<Control> actions = new List<Control>();
        private readonly Brush ink = new SolidColorBrush(Color.FromRgb(24, 42, 65));
        private readonly Brush muted = new SolidColorBrush(Color.FromRgb(93, 111, 132));
        private readonly Brush teal = new SolidColorBrush(Color.FromRgb(20, 134, 128));
        private readonly Brush line = new SolidColorBrush(Color.FromRgb(222, 230, 240));
        private string S(string key) => AppStrings.Get(key, language);
        private string R(string key) => ReportText.Get(key, language);

        public MainWindow() : this(null) { }

        public MainWindow(string startupPath)
        {
            Title = S("Title"); Width = 1200; Height = 850; MinWidth = 900; MinHeight = 650;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            FontFamily = new FontFamily("Segoe UI"); FontSize = 14; Foreground = ink;
            Background = new SolidColorBrush(Color.FromRgb(243, 246, 250));
            Closing += OnClosing;
            Render();
            if (startupPath != null) Loaded += async (s, e) => await OpenSnapshotFromUiAsync(startupPath);
        }

        private void OnClosing(object sender, CancelEventArgs e)
        {
            if (!busy) return;
            e.Cancel = true;
            MessageBox.Show(this, S("WaitForCollection"), S("Title"), MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private TextBlock Text(string value, double size = 14, bool bold = false)
        {
            return new TextBlock { Text = value ?? "", FontSize = size, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
        }
        private Border Card(UIElement child, Brush stripe = null)
        {
            return new Border { Background = Brushes.White, BorderBrush = stripe ?? line, BorderThickness = stripe == null ? new Thickness(1) : new Thickness(5, 1, 1, 1),
                CornerRadius = new CornerRadius(10), Padding = new Thickness(22), Margin = new Thickness(0, 0, 0, 14), Child = child };
        }
        private Button Action(string key, RoutedEventHandler handler, bool primary = false, bool requiresReport = false)
        {
            var button = new Button { Content = S(key), Padding = new Thickness(16, 9, 16, 9), Margin = new Thickness(0, 0, 8, 0),
                Background = primary ? teal : Brushes.White, Foreground = primary ? Brushes.White : ink, BorderBrush = primary ? teal : line,
                BorderThickness = new Thickness(1), Cursor = System.Windows.Input.Cursors.Hand, IsEnabled = !busy && (!requiresReport || report != null) };
            button.Opacity = button.IsEnabled ? 1 : 0.45;
            AutomationProperties.SetAutomationId(button, key);
            button.Click += handler; actions.Add(button); return button;
        }
        private ScrollViewer Scroll(UIElement content) => new ScrollViewer { Content = content, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new Thickness(6, 16, 10, 4) };

        private void Render()
        {
            actions.Clear();
            var root = new DockPanel { LastChildFill = true, Background = Background };
            System.Windows.Documents.TextElement.SetFontFamily(root, FontFamily);
            System.Windows.Documents.TextElement.SetFontSize(root, FontSize);
            System.Windows.Documents.TextElement.SetForeground(root, Foreground);
            var heading = new Grid { Background = ink, Margin = new Thickness(0, 0, 0, 0) };
            heading.ColumnDefinitions.Add(new ColumnDefinition()); heading.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var brand = new StackPanel { Margin = new Thickness(28, 18, 20, 18) };
            brand.Children.Add(new TextBlock { Text = S("Title"), FontSize = 25, FontWeight = FontWeights.SemiBold, Foreground = Brushes.White });
            brand.Children.Add(new TextBlock { Text = S("Tagline"), Foreground = new SolidColorBrush(Color.FromRgb(181, 204, 220)), Margin = new Thickness(0, 4, 0, 0) });
            heading.Children.Add(brand);
            var langs = new ComboBox { Width = 130, Margin = new Thickness(16, 20, 28, 20), VerticalAlignment = VerticalAlignment.Center,
                ItemsSource = new[] { AppStrings.Get("Russian", "ru"), AppStrings.Get("English", "en") }, SelectedIndex = language == "ru" ? 0 : 1, IsEnabled = !busy };
            AutomationProperties.SetName(langs, S("Language"));
            langs.SelectionChanged += (s, e) => { var next = langs.SelectedIndex == 0 ? "ru" : "en"; if (next == language) return; language = next;
                CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(language); CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(language);
                if (snapshot != null) report = Report.Build(snapshot, analysis, language); Render(); };
            Grid.SetColumn(langs, 1); heading.Children.Add(langs); actions.Add(langs);
            DockPanel.SetDock(heading, Dock.Top); root.Children.Add(heading);
            var toolbar = new StackPanel { Margin = new Thickness(28, 20, 28, 8) };
            var buttons = new WrapPanel();
            buttons.Children.Add(Action("Diagnose", async (s, e) => await CollectAsync(), true));
            buttons.Children.Add(Action("OpenSnapshot", async (s, e) => { var d = new OpenFileDialog { Filter = S("SnapshotFilter"), Title = S("OpenSnapshot") }; if (d.ShowDialog(this) == true) await OpenSnapshotFromUiAsync(d.FileName); }));
            buttons.Children.Add(Action("ExportHtml", (s, e) => Export(true), requiresReport: true));
            buttons.Children.Add(Action("ExportJson", (s, e) => Export(false), requiresReport: true));
            toolbar.Children.Add(buttons);
            var options = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            consent = new CheckBox { Content = S("ExternalConsent"), IsChecked = false, IsEnabled = !busy, Margin = new Thickness(0, 0, 28, 8) };
            mask = new CheckBox { Content = S("MaskExports"), IsChecked = true, IsEnabled = !busy, Margin = new Thickness(0, 0, 0, 8) };
            options.Children.Add(consent); options.Children.Add(mask); actions.Add(consent); actions.Add(mask); toolbar.Children.Add(options);
            DockPanel.SetDock(toolbar, Dock.Top); root.Children.Add(toolbar);
            var footer = new StackPanel { Margin = new Thickness(28, 6, 28, 16) };
            status = Text(S(statusKey), 12); status.Foreground = muted;
            progress = new ProgressBar { Height = 4, Minimum = 0, Maximum = 13, Visibility = busy ? Visibility.Visible : Visibility.Collapsed, IsIndeterminate = busy };
            footer.Children.Add(status); footer.Children.Add(progress); DockPanel.SetDock(footer, Dock.Bottom); root.Children.Add(footer);
            var body = new Grid { Margin = new Thickness(28, 6, 28, 0) };
            if (report == null)
            {
                var empty = new StackPanel { MaxWidth = 720, Margin = new Thickness(32), VerticalAlignment = VerticalAlignment.Center };
                empty.Children.Add(Text(S("WelcomeTitle"), 32, true)); empty.Children.Add(Text(S("WelcomeBody"), 17));
                empty.Children.Add(Text(S("WelcomeDetails"))); body.Children.Add(Card(empty));
            }
            else
            {
                var tabs = new TabControl { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0) };
                AddTab(tabs, "Overview", Scroll(Overview()));
                AddTab(tabs, "Network", Scroll(Network()));
                AddTab(tabs, "Charts", ChartViews.Create(report, language));
                AddTab(tabs, "Services", Scroll(Services()));
                AddTab(tabs, "Hardware", Scroll(Hardware()));
                AddTab(tabs, "Appendix", Scroll(Appendix())); body.Children.Add(tabs);
            }
            root.Children.Add(body); Content = root;
        }
        private void AddTab(TabControl tabs, string key, UIElement child) => tabs.Items.Add(new TabItem { Header = S(key), Content = child, Padding = new Thickness(14, 9, 14, 9) });
        private object Data(string module) => JsonValue.Get(report.Root["sections"], module);
        private IEnumerable<object> Checks => JsonValue.GetList(report.Root, "checks");
        private string Value(object row, string path)
        {
            object value = row;
            foreach (var key in path.Split('.')) value = JsonValue.Get(value, key);
            if (value == null) return S("Unknown");
            if (value is string && new[] { "state", "status", "startMode", "healthStatus" }.Contains(path)) return AppStrings.Data((string)value, language);
            if (value is bool) return S((bool)value ? "Yes" : "No");
            if (path.EndsWith("Bytes", StringComparison.Ordinal) && JsonValue.IsNumber(value)) return (Convert.ToDouble(value, CultureInfo.InvariantCulture) / 1073741824).ToString("N1", CultureInfo.CurrentCulture) + " " + S("GiB");
            var list = JsonValue.AsList(value);
            return list != null ? string.Join(", ", list.Select(v => Convert.ToString(v, CultureInfo.CurrentCulture))) : Convert.ToString(value, CultureInfo.CurrentCulture);
        }
        private UIElement Table(object values, params string[] columns)
        {
            var rows = JsonValue.AsList(values);
            if (rows == null || rows.Count == 0) return Text(R("NoData"));
            var grid = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true, CanUserAddRows = false, CanUserDeleteRows = false,
                HeadersVisibility = DataGridHeadersVisibility.Column, GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                BorderThickness = new Thickness(0), RowHeaderWidth = 0, MaxHeight = 310, MinHeight = 65, Margin = new Thickness(0, 0, 0, 12),
                EnableRowVirtualization = true, EnableColumnVirtualization = true, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
            var data = rows.Select(row => columns.Select(c => Value(row, c.Split('|')[1])).ToArray()).ToArray();
            for (int i = 0; i < columns.Length; i++) grid.Columns.Add(new DataGridTextColumn { Header = S(columns[i].Split('|')[0]), Binding = new Binding("[" + i + "]"), Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 100 });
            grid.ItemsSource = data; return grid;
        }
        private Expander Technical(object data, string header = null) => new Expander { Header = header ?? S("TechnicalDetails"), Margin = new Thickness(0, 8, 0, 8),
            Content = new TextBox { Text = JsonValue.Serialize(data), IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 300,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas"), FontSize = 12, BorderBrush = line, Padding = new Thickness(10) } };
        private void Section(StackPanel panel, string title, UIElement content)
        { var inner = new StackPanel(); inner.Children.Add(Text(title, 20, true)); inner.Children.Add(content); panel.Children.Add(Card(inner)); }

        private UIElement Overview()
        {
            var panel = new StackPanel(); var summary = JsonValue.AsObject(report.Root["summary"]);
            var score = (string)summary["score"];
            var color = score == "red" ? Brushes.Crimson : score == "yellow" ? Brushes.DarkGoldenrod : score == "green" ? teal : Brushes.SlateGray;
            var lead = new StackPanel(); lead.Children.Add(Text(R("Score_" + score), 27, true));
            var mode = Text(ReportText.CollectionMode(report, language), 14, true);
            AutomationProperties.SetAutomationId(mode, "CollectionMode");
            lead.Children.Add(mode);
            lead.Children.Add(Text(S("ScoreScope"))); lead.Children.Add(Text(S("SnapshotDate") + " " + snapshot.CreatedAtUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), 12));
            var counts = new WrapPanel(); foreach (var p in JsonValue.AsObject(summary["counts"])) counts.Children.Add(new TextBlock { Text = R("Level_" + p.Key) + ": " + p.Value, Margin = new Thickness(0, 8, 24, 0), FontWeight = FontWeights.SemiBold });
            lead.Children.Add(counts); panel.Children.Add(Card(lead, color));
            var top = new StackPanel();
            foreach (var id in JsonValue.GetList(summary, "recommendations"))
            { var check = Checks.Single(c => Equals(JsonValue.Get(c, "id"), id)); top.Children.Add(Text(Value(check, "title"), 16, true)); top.Children.Add(Text(Value(check, "fix"))); }
            if (top.Children.Count == 0) top.Children.Add(Text(S("NoRecommendations")));
            Section(panel, R("Recommendations"), top);
            panel.Children.Add(Text(R("Findings"), 21, true));
            var found = Checks.Where(c => Equals(JsonValue.Get(c, "status"), "found")).ToList();
            if (found.Count == 0) panel.Children.Add(Card(Text(S("NoFindings"))));
            foreach (var check in found)
            {
                var card = new StackPanel(); var level = Value(check, "level");
                card.Children.Add(Text(R("Level_" + level) + (Equals(JsonValue.Get(check, "experimental"), true) ? " · " + R("Experimental") : ""), 12, true));
                card.Children.Add(Text(Value(check, "title"), 20, true)); card.Children.Add(Text(Value(check, "why")));
                card.Children.Add(Text(R("Fix"), 14, true)); card.Children.Add(Text(Value(check, "fix")));
                var details = new StackPanel(); details.Children.Add(Text(Value(check, "details")));
                foreach (var group in JsonValue.GetList(check, "evidence").GroupBy(e => JsonValue.AsString(JsonValue.Get(JsonValue.Get(e, "values"), "address")) ?? ""))
                    details.Children.Add(Technical(group.ToArray(), (group.Key.Length == 0 ? S("Evidence") : group.Key) + " · " + group.Count()));
                if (JsonValue.GetList(check, "limitations").Count > 0) details.Children.Add(Technical(JsonValue.Get(check, "limitations"), S("Limitations")));
                card.Children.Add(new Expander { Header = S("TechnicalDetails") + " · " + Value(check, "evidenceCount"), Content = details });
                panel.Children.Add(Card(card, level == "critical" ? Brushes.Crimson : level == "important" ? Brushes.DarkGoldenrod : line));
            }
            var coverage = new StackPanel();
            foreach (var check in Checks.Where(c => !Equals(JsonValue.Get(c, "status"), "found")))
            {
                var d = new StackPanel(); d.Children.Add(Text(Value(check, "hint")));
                d.Children.Add(Technical(new { reason = JsonValue.Get(check, "reason"), limitations = JsonValue.Get(check, "limitations") }));
                coverage.Children.Add(new Expander { Header = Value(check, "title") + " · " + R("Status_" + Value(check, "status")), Content = d, Margin = new Thickness(0, 3, 0, 5) });
            }
            Section(panel, R("Coverage"), coverage); return panel;
        }
        private UIElement Network()
        {
            var p = new StackPanel();
            var map = new WrapPanel();
            foreach (var routes in JsonValue.GetList(Data("routing"), "routes").GroupBy(r => Value(r, "interfaceAlias")))
            {
                var group = new StackPanel { Width = 315, Margin = new Thickness(0, 0, 14, 12) };
                group.Children.Add(Text(routes.Key, 16, true));
                foreach (var route in routes) group.Children.Add(Text(string.Format(CultureInfo.CurrentCulture, S("RouteLine"), Value(route, "nextHop"), Value(route, "destinationPrefix")), 12));
                map.Children.Add(Card(group, teal));
            }
            Section(p, S("NetworkMap"), map.Children.Count == 0 ? (UIElement)Text(R("NoData")) : map);
            Section(p, S("Adapters"), Table(JsonValue.Get(Data("adapters"), "adapters"), "Name|name", "Status|status", "Description|interfaceDescription", "Mtu|mtuSize"));
            Section(p, S("Routes"), Table(JsonValue.Get(Data("routing"), "routes"), "Adapter|interfaceAlias", "Prefix|destinationPrefix", "Gateway|nextHop", "Metric|effectiveMetric"));
            Section(p, S("Dns"), Table(JsonValue.Get(Data("dns-proxy"), "dnsServers"), "Adapter|interfaceAlias", "Address|serverAddresses"));
            Section(p, S("ThirdPartyVpn"), Table(JsonValue.Get(Data("vpn"), "clients"), "Name|name", "Type|kind"));
            p.Children.Add(BuiltInVpnView.Create(report, language));
            Section(p, S("Wifi"), Table(JsonValue.Get(Data("wifi"), "interfaces"), "Name|name", "Ssid|ssid", "Channel|channel", "Signal|signalPercent", "Radio|radioType"));
            Section(p, S("Proxy"), Technical(JsonValue.Get(Data("dns-proxy"), "proxy")));
            var wifiModule = JsonValue.GetList(report.Root, "modules").FirstOrDefault(m => Equals(JsonValue.Get(m, "name"), "wifi"));
            if (!JsonValue.GetList(wifiModule, "errors").Any(e => Equals(JsonValue.Get(e, "kind"), "AccessDenied"))) return p;
            var location = new StackPanel(); location.Children.Add(Text(S("LocationHint")));
            var settings = new Button { Content = S("OpenLocation"), HorizontalAlignment = HorizontalAlignment.Left, Padding = new Thickness(12, 6, 12, 6) };
            settings.Click += (s, e) => { try { Process.Start(new ProcessStartInfo("ms-settings:privacy-location") { UseShellExecute = true }); } catch (Win32Exception) { ShowError("SettingsError"); } };
            location.Children.Add(settings); Section(p, S("WifiPermissions"), location);
            return p;
        }
        private UIElement Services()
        {
            var p = new StackPanel(); var data = Data("services");
            Section(p, S("Services"), Table(JsonValue.Get(data, "services"), "Name|displayName", "Status|state", "StartMode|startMode", "Image|imagePath"));
            Section(p, S("Startup"), Table(JsonValue.Get(data, "autostart"), "Name|name", "Enabled|enabled", "Image|imagePath"));
            Section(p, S("Drivers"), Table(JsonValue.Get(data, "drivers"), "Name|displayName", "Status|state", "Image|imagePath")); return p;
        }
        private UIElement Hardware()
        {
            var p = new StackPanel(); var h = Data("hardware");
            Section(p, S("Cpu"), Table(JsonValue.Get(h, "cpus"), "Model|name", "Cores|cores", "Threads|logicalProcessors", "Clock|maxClockMhz"));
            Section(p, S("Memory"), Table(JsonValue.Get(JsonValue.Get(h, "memory"), "modules"), "PartNumber|partNumber", "Bytes|capacityBytes", "MemorySpeed|configuredSpeedMts"));
            Section(p, S("Gpu"), Table(JsonValue.Get(h, "gpus"), "Model|name", "MemoryBytes|memoryBytes"));
            Section(p, S("Disks"), Table(JsonValue.Get(h, "disks"), "Model|friendlyName", "Type|mediaType", "Bytes|sizeBytes", "Health|healthStatus"));
            Section(p, S("BoardBios"), Technical(new { board = JsonValue.Get(h, "board"), bios = JsonValue.Get(h, "bios") })); return p;
        }
        private UIElement Appendix()
        {
            var p = new StackPanel(); var mods = JsonValue.GetList(report.Root, "modules").Select(m => (object)new Dictionary<string, object>
                { ["name"] = R("Module_" + JsonValue.Get(m, "name")), ["status"] = R("ModuleStatus_" + JsonValue.Get(m, "status")), ["errors"] = JsonValue.GetList(m, "errors").Count }).ToArray();
            Section(p, S("Modules"), Table(mods, "Module|name", "Status|status", "Errors|errors"));
            foreach (var m in JsonValue.GetList(report.Root, "modules").Where(m => JsonValue.GetList(m, "errors").Count > 0))
                p.Children.Add(Technical(JsonValue.Get(m, "errors"), R("Module_" + JsonValue.Get(m, "name"))));
            p.Children.Add(Technical(new { ruleErrors = report.Root["ruleErrors"], evaluationErrors = report.Root["evaluationErrors"] }, S("AnalysisErrors")));
            return p;
        }

        private void SetBusy(bool value, string key)
        {
            busy = value; statusKey = key; Render();
        }
        private void ShowError(string key) => MessageBox.Show(this, S(key), S("Title"), MessageBoxButton.OK, MessageBoxImage.Warning);
        public async Task OpenSnapshotAsync(string path)
        {
            if (busy) return;
            SetBusy(true, "Analyzing");
            try { await LoadAsync(path); statusKey = "Loaded"; }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is SnapshotFormatException || e is InvalidOperationException)
            { statusKey = "OpenFailed"; throw; }
            finally { busy = false; Render(); }
        }
        private async Task OpenSnapshotFromUiAsync(string path)
        {
            try { await OpenSnapshotAsync(path); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is SnapshotFormatException || e is InvalidOperationException)
            { ShowError("OpenFailed"); }
        }
        private async Task LoadAsync(string path)
        {
            var result = await Task.Run(() => {
                var s = Snapshot.Load(path); var catalog = FactCatalog.CreateDefault();
                var rules = RuleLoader.LoadDirectory(Path.Combine(Path.GetDirectoryName(new Uri(typeof(MainWindow).Assembly.CodeBase).LocalPath), "rules"), catalog);
                var a = new RuleEngine(catalog).Evaluate(s, rules.Rules, rules.Errors);
                return Tuple.Create(s, a, Report.Build(s, a, language));
            });
            sourcePath = Path.GetFullPath(path);
            snapshot = result.Item1; analysis = result.Item2; report = result.Item3;
        }
        private async Task CollectAsync()
        {
            if (busy) return;
            bool external = consent.IsChecked == true;
            SetBusy(true, "Collecting");
            try
            {
                var events = new Progress<CollectionProgress>(p => {
                    if (!busy) return;
                    if (p.Status == "notElevated") { status.Text = S("NotElevatedFallback"); return; }
                    if (p.Status == "slow") { status.Text = S("SlowCollection"); return; }
                    progress.IsIndeterminate = p.Total <= 0; progress.Maximum = Math.Max(1, p.Total); progress.Value = p.Done;
                    status.Text = string.Format(CultureInfo.CurrentCulture, S("CollectionProgress"), p.Done, p.Total, string.IsNullOrEmpty(p.Module) ? "" : R("Module_" + p.Module));
                });
                var result = await new CollectionRunner().RunAsync(external, events);
                status.Text = S("Analyzing"); progress.IsIndeterminate = true;
                await LoadAsync(result.SnapshotPath); statusKey = "Loaded";
            }
            catch (Exception e) when (e is CollectionRunException || e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is SnapshotFormatException || e is InvalidOperationException)
            { statusKey = "CollectionFailed"; ShowError("CollectionFailed"); }
            finally { busy = false; Render(); }
        }
        private void Export(bool html)
        {
            if (report == null || busy) return;
            var dialog = new SaveFileDialog { Filter = S(html ? "HtmlFilter" : "ReportFilter"), DefaultExt = html ? ".html" : ".json", FileName = html ? "TunnelEye-report.html" : "TunnelEye-report.json", Title = S("ExportTitle") };
            if (dialog.ShowDialog(this) != true) return;
            try
            {
                if (string.Equals(Path.GetFullPath(dialog.FileName), sourcePath, StringComparison.OrdinalIgnoreCase)) { ShowError("OutputCollision"); return; }
                var output = mask.IsChecked == true ? report.Masked(new PrivacyMasker(snapshot)) : report;
                File.WriteAllText(dialog.FileName, html ? HtmlReport.Write(output) : output.Json(), new UTF8Encoding(false));
                status.Text = S("Exported");
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) { ShowError("ExportFailed"); }
        }
    }
}
