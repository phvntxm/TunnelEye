// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Argus.Core.Engine;
using Argus.Core.Facts;
using Argus.Core.Json;
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

        public static Snapshot LoadSnapshot(string name) => Snapshot.Parse(JsonValue.Serialize(LoadTree(name)));

        /// <summary>
        /// The JSON tree of a test snapshot. A file is either a whole snapshot
        /// or an overlay {"schema": "tunneleye.test-overlay/1", "base": name,
        /// "patch": {...}}: the patch is merged into the base (itself possibly
        /// an overlay) - objects key by key, anything else (arrays, values,
        /// null) replaces. So a problem snapshot holds only its problem, and
        /// the clean base grows in one place.
        /// </summary>
        public static IDictionary<string, object> LoadTree(string name)
        {
            var tree = JsonValue.AsObject(JsonValue.Parse(File.ReadAllText(Path.Combine(SnapshotsDir, name + ".json"), Encoding.UTF8)));
            if (JsonValue.AsString(JsonValue.Get(tree, "schema")) != "tunneleye.test-overlay/1") return tree;
            var result = LoadTree(JsonValue.AsString(tree["base"]));
            Merge(result, JsonValue.AsObject(tree["patch"]));
            return result;
        }

        private static void Merge(IDictionary<string, object> target, IDictionary<string, object> patch)
        {
            foreach (var pair in patch)
            {
                object existing;
                var from = JsonValue.AsObject(pair.Value);
                if (from != null && target.TryGetValue(pair.Key, out existing) && JsonValue.AsObject(existing) != null) Merge(JsonValue.AsObject(existing), from);
                else target[pair.Key] = pair.Value;
            }
        }

        /// <summary>Test snapshots: whole files and overlays.</summary>
        public static IEnumerable<string> SnapshotNames() => Directory.GetFiles(SnapshotsDir, "*.json").Select(Path.GetFileNameWithoutExtension);

        public static RuleLoader.LoadResult LoadRules() => RuleLoader.LoadDirectory(RulesDir, FactCatalog.CreateDefault());

        public static AnalysisResult Analyze(Snapshot snapshot)
        {
            var catalog = FactCatalog.CreateDefault();
            var rules = RuleLoader.LoadDirectory(RulesDir, catalog);
            return new RuleEngine(catalog).Evaluate(snapshot, rules.Rules, rules.Errors);
        }
    }
}
