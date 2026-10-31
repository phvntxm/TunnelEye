// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Resources;
using System.Text;
using Argus.Core.Engine;
using Argus.Core.Json;
using Argus.Core.Facts;
using Argus.Core.Rules;
using Argus.Core.Reports;
using Argus.Core.Snapshots;

namespace TunnelEye.Cli
{
    /// <summary>
    /// tunneleye analyze &lt;snapshot.json&gt; [--rules &lt;dir&gt;] [--json &lt;file&gt;]
    /// Exit codes: 0 analysis done, 2 usage error, 3 snapshot or rules error.
    /// </summary>
    internal static class Program
    {
        private static readonly ResourceManager Strings = new ResourceManager("TunnelEye.Cli.Strings", typeof(Program).Assembly);

        private static string S(string name) => Strings.GetString(name, CultureInfo.CurrentUICulture) ?? name;

        private static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length < 2 || args[0] != "analyze")
            {
                Console.Error.WriteLine(S("Usage"));
                return 2;
            }
            var snapshotPath = args[1];
            string rulesDir = null, jsonOut = null, reportOut = null, htmlOut = null, snapshotOut = null, language = "ru";
            bool mask = false;
            for (var i = 2; i < args.Length; i++)
            {
                if (args[i] == "--rules" && i + 1 < args.Length) rulesDir = args[++i];
                else if (args[i] == "--json" && i + 1 < args.Length) jsonOut = args[++i];
                else if (args[i] == "--report-json" && i + 1 < args.Length) reportOut = args[++i];
                else if (args[i] == "--html" && i + 1 < args.Length) htmlOut = args[++i];
                else if (args[i] == "--snapshot-json" && i + 1 < args.Length) snapshotOut = args[++i];
                else if (args[i] == "--mask") mask = true;
                else if (args[i] == "--lang" && i + 1 < args.Length) language = args[++i];
                else { Console.Error.WriteLine(S("Usage")); return 2; }
            }
            if (language != "ru" && language != "en") { Console.Error.WriteLine(S("Usage")); return 2; }
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(language);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(language);
            try
            {
                var paths = new[] { jsonOut, reportOut, htmlOut, snapshotOut }.Where(p => p != null).Select(Path.GetFullPath).ToArray();
                if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length || paths.Contains(Path.GetFullPath(snapshotPath), StringComparer.OrdinalIgnoreCase))
                { Console.Error.WriteLine(S("OutputCollision")); return 2; }
            }
            catch (Exception e) when (e is ArgumentException || e is NotSupportedException || e is PathTooLongException)
            { Console.Error.WriteLine(S("OutputCollision")); return 2; }
            if (rulesDir == null) rulesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");

            Snapshot snapshot;
            try { snapshot = Snapshot.Load(snapshotPath); }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is SnapshotFormatException || e is ArgumentException)
            {
                Console.Error.WriteLine(string.Format(CultureInfo.CurrentCulture, S("SnapshotError"), e.Message));
                return 3;
            }
            if (!Directory.Exists(rulesDir))
            {
                Console.Error.WriteLine(string.Format(CultureInfo.CurrentCulture, S("RulesMissing"), rulesDir));
                return 3;
            }

            var catalog = FactCatalog.CreateDefault();
            var loaded = RuleLoader.LoadDirectory(rulesDir, catalog);
            foreach (var error in loaded.Errors) Console.Error.WriteLine(string.Format(CultureInfo.CurrentCulture, S("RuleError"), error));
            var analysis = new RuleEngine(catalog).Evaluate(snapshot, loaded.Rules, loaded.Errors);

            var report = Report.Build(snapshot, analysis, language);
            var masker = mask ? new PrivacyMasker(snapshot) : null;
            if (masker != null) report = report.Masked(masker);
            var summary = JsonValue.AsObject(report.Root["summary"]);
            Console.WriteLine(ReportText.Get("Score_" + summary["score"], language));
            foreach (var check in JsonValue.GetList(report.Root, "checks"))
                Console.WriteLine("[{0}] {1} ({2})", ReportText.Get("Status_" + JsonValue.Get(check, "status"), language), JsonValue.Get(check, "title"), JsonValue.Get(check, "id"));
            try
            {
                if (jsonOut != null)
                {
                    var raw = AnalysisJson.Write(analysis);
                    File.WriteAllText(jsonOut, masker == null ? raw : JsonValue.Serialize(masker.Transform(JsonValue.Parse(raw))), new UTF8Encoding(false));
                }
                if (reportOut != null) File.WriteAllText(reportOut, report.Json(), new UTF8Encoding(false));
                if (htmlOut != null) File.WriteAllText(htmlOut, HtmlReport.Write(report), new UTF8Encoding(false));
                if (snapshotOut != null) File.WriteAllText(snapshotOut, masker == null ? JsonValue.Serialize(snapshot.Root) : masker.SnapshotJson(snapshot), new UTF8Encoding(false));
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is NotSupportedException)
            { Console.Error.WriteLine(S("ExportError")); return 3; }
            return 0;
        }
    }
}
