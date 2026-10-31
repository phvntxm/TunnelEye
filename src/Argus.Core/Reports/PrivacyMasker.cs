// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Argus.Core.Json;
using Argus.Core.Snapshots;

namespace Argus.Core.Reports
{
    /// <summary>One export-scoped map for snapshot, report and embedded evidence.
    /// It is never serialized and does not change the source snapshot.</summary>
    public sealed class PrivacyMasker
    {
        private readonly Dictionary<string, string> tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> counts = new Dictionary<string, int>();
        private Regex replacements;
        private static readonly Regex Mac = new Regex(@"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex Address = new Regex(@"(?<![\w])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w])|(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%[\w-]+)?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public PrivacyMasker(Snapshot snapshot)
        {
            Discover(snapshot.Root, "");
            if (tokens.Count > 0) replacements = new Regex(string.Join("|", tokens.Keys.OrderByDescending(k => k.Length).ThenBy(k => k, StringComparer.Ordinal).Select(Regex.Escape)), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        private void Add(string value, string kind)
        {
            if (string.IsNullOrWhiteSpace(value) || tokens.ContainsKey(value)) return;
            int n; counts.TryGetValue(kind, out n); counts[kind] = ++n;
            tokens[value] = kind + "-" + n;
        }

        private void Discover(object value, string path)
        {
            var obj = JsonValue.AsObject(value);
            if (obj != null)
            {
                foreach (var pair in obj) Discover(pair.Value, path + "." + pair.Key);
                return;
            }
            var list = JsonValue.AsList(value);
            if (list != null) { foreach (var item in list) Discover(item, path + "[]"); return; }
            var s = value as string;
            if (s == null) return;
            foreach (Match m in Mac.Matches(s)) Add(m.Value, "MAC");
            foreach (Match m in Address.Matches(s)) { IPAddress ip; if (IPAddress.TryParse(m.Value, out ip)) Add(m.Value, "IP"); }
            var lower = path.ToLowerInvariant();
            if (lower.EndsWith(".ssid")) Add(s, "SSID");
            else if (lower.Contains(".networkprofiles[]") && lower.EndsWith(".name")) Add(s, "NETWORK");
            else if (lower.Contains(".builtin.profiles[]") && (lower.EndsWith(".name") || lower.EndsWith(".friendlyname"))) Add(s, "VPN");
            else if (lower.Contains(".builtin.profiles[]") && lower.EndsWith(".serveraddress")) Add(s, "SERVER");
            else if (lower.EndsWith(".serveraddress") || lower.EndsWith(".proxyserver") || lower.EndsWith(".autoconfigurl") || lower.EndsWith(".pacurl") || (lower.Contains("proxies[]") && lower.EndsWith(".host")))
            {
                Add(s, "SERVER");
                Uri uri; if (Uri.TryCreate(s, UriKind.Absolute, out uri) && !string.IsNullOrEmpty(uri.Host)) Add(uri.Host, "SERVER");
            }
            else if (lower.Contains("suffix") && !lower.EndsWith(".suffixorigin")) Add(s, "DNS");
            else if (lower.EndsWith(".computer.name") || lower.EndsWith(".computer.domain") || lower.EndsWith(".computer.workgroup") || lower.EndsWith(".computername") || lower.EndsWith(".hostname")) Add(s, "HOST");
            else if (lower.EndsWith(".username") || lower.EndsWith(".user")) Add(s, "USER");
            foreach (Match m in Regex.Matches(s, @"(?i)[A-Z]:\\Users\\([^\\/]+)")) Add(m.Groups[1].Value, "USER");
        }

        private string Replace(string value)
        {
            var result = replacements == null ? value : replacements.Replace(value, m => tokens[m.Value]);
            // Analysis errors may contain paths that are absent from the snapshot.
            result = Regex.Replace(result, @"(?i)([A-Z]:\\Users\\)([^\\/]+)", m => { Add(m.Groups[2].Value, "USER"); return m.Groups[1].Value + tokens[m.Groups[2].Value]; });
            result = Mac.Replace(result, m => { Add(m.Value, "MAC"); return tokens[m.Value]; });
            return Address.Replace(result, m => { IPAddress ip; if (!IPAddress.TryParse(m.Value, out ip)) return m.Value; Add(m.Value, "IP"); return tokens[m.Value]; });
        }

        public object Transform(object value) => TransformValue(value, "");

        private object TransformValue(object value, string path)
        {
            var obj = JsonValue.AsObject(value);
            if (obj != null) return obj.ToDictionary(p => p.Key, p => p.Key == "masked" ? (object)true :
                IsMetadata(p.Key, path) ? p.Value : TransformValue(p.Value, path + "." + p.Key), StringComparer.Ordinal);
            var list = JsonValue.AsList(value);
            if (list != null) return list.Select(item => TransformValue(item, path + "[]")).ToArray();
            return value is string ? Replace((string)value) : value;
        }

        // Protocol identifiers remain stable even when an SSID is literally "ru"
        // or a computer is called "system". Sensitive fields still get replaced.
        private static bool IsMetadata(string key, string path)
        {
            return new[] { "schema", "language", "status", "level", "id", "ruleId", "score", "facts", "version", "createdAt", "snapshotId", "recommendations", "incompleteCritical", "sources" }.Contains(key)
                || (path == ".modules[]" && key == "name");
        }

        public string SnapshotJson(Snapshot snapshot) => JsonValue.Serialize(Transform(snapshot.Root));
    }
}
