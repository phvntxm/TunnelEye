// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Resources;
using System.Text;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Rules;
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
            string rulesDir = null, jsonOut = null;
            for (var i = 2; i < args.Length; i++)
            {
                if (args[i] == "--rules" && i + 1 < args.Length) rulesDir = args[++i];
                else if (args[i] == "--json" && i + 1 < args.Length) jsonOut = args[++i];
                else { Console.Error.WriteLine(S("Usage")); return 2; }
            }
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

            var culture = CultureInfo.CurrentUICulture.Name;
            foreach (var r in analysis.Results.OrderBy(r => r.Status).ThenBy(r => r.Rule.Level))
            {
                var title = r.Rule.Text["title"].For(culture);
                var status = S("Status_" + AnalysisJson.StatusName(r.Status));
                var line = string.Format(CultureInfo.CurrentCulture, "[{0}] {1} ({2})", status, title, r.Rule.Id);
                if (r.Status == RuleStatus.NotChecked) line += " - " + r.Reason;
                Console.WriteLine(line);
            }
            if (jsonOut != null) File.WriteAllText(jsonOut, AnalysisJson.Write(analysis), new UTF8Encoding(false));
            return 0;
        }
    }
}
