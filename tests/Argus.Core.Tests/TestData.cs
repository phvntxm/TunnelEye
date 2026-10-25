// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.IO;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Rules;
using Argus.Core.Snapshots;

namespace Argus.Core.Tests
{
    /// <summary>Paths of the repository and loaded rules/snapshots for tests.</summary>
    internal static class TestData
    {
        private static readonly Lazy<string> Root = new Lazy<string>(() =>
        {
            var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "CLAUDE.md"))) dir = dir.Parent;
            if (dir == null) throw new InvalidOperationException("Repository root (CLAUDE.md) not found.");
            return dir.FullName;
        });

        public static string RepoRoot => Root.Value;
        public static string RulesDir => Path.Combine(RepoRoot, "rules");
        public static string SnapshotsDir => Path.Combine(RepoRoot, "tests", "snapshots");
        public static string LocalRegressDir => Path.Combine(RepoRoot, ".local", "regress");

        public static Snapshot LoadSnapshot(string name) => Snapshot.Load(Path.Combine(SnapshotsDir, name + ".json"));

        public static RuleLoader.LoadResult LoadRules() => RuleLoader.LoadDirectory(RulesDir, FactCatalog.CreateDefault());

        public static AnalysisResult Analyze(Snapshot snapshot)
        {
            var catalog = FactCatalog.CreateDefault();
            var rules = RuleLoader.LoadDirectory(RulesDir, catalog);
            return new RuleEngine(catalog).Evaluate(snapshot, rules.Rules, rules.Errors);
        }
    }
}
