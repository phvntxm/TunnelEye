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
    /// <summary>One export-scoped map shared by snapshot, report and evidence.
    /// Replacements are applied to original text once, never to generated tokens.</summary>
    public sealed class PrivacyMasker
    {
        private const string MacPattern = @"(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])";
        private const string AddressPattern = @"(?<![\w])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w])|(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%[\w-]+)?";
        private const string ProfilePattern = @"(?<profilePrefix>[a-z]:\\Users\\)(?<profileUser>[^\\/\r\n""<>]+)";
        private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);
        private static readonly Regex Mac = Pattern(MacPattern);
        private static readonly Regex Address = Pattern(AddressPattern);
        private static readonly Regex Profile = Pattern(ProfilePattern);
        private static readonly HashSet<string> Metadata = new HashSet<string>(StringComparer.Ordinal)
        { "schema", "language", "status", "level", "id", "ruleId", "score", "facts", "version", "createdAt", "snapshotId", "recommendations", "incompleteCritical", "sources" };
        private static readonly HashSet<string> HardwareLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "model", "partNumber", "name", "product", "manufacturer", "version", "driverVersion", "smbiosVersion" };
        private readonly Dictionary<string, string> tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> identities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> counts = new Dictionary<string, int>();
        private readonly Regex replacements;

        public PrivacyMasker(Snapshot snapshot)
        {
            if (snapshot == null) throw new ArgumentNullException(nameof(snapshot));
            Discover(snapshot.Root, "");
            // Longer literals and complete addresses win over short identities.
            var literals = identities.Keys.OrderByDescending(k => k.Length).ThenBy(k => k, StringComparer.Ordinal)
                .Select(k => @"(?<![\p{L}\p{N}_])" + Regex.Escape(k) + @"(?![\p{L}\p{N}_])").ToArray();
            var literalPattern = literals.Length == 0 ? "(?!)" : string.Join("|", literals);
            replacements = Pattern("(?<profile>" + ProfilePattern + ")|(?<mac>" + MacPattern + ")|(?<address>" + AddressPattern + ")|(?<identity>" + literalPattern + ")");
        }

        private static Regex Pattern(string expression) => new Regex(expression, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, MatchTimeout);

        private string Token(string value, string kind)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;
            if (kind == "IP")
            {
                IPAddress parsed;
                if (IPAddress.TryParse(value, out parsed)) value = parsed.ToString();
            }
            else if (kind == "MAC") value = value.Replace(":", "").Replace("-", "");
            var key = kind + ":" + value;
            string token;
            if (tokens.TryGetValue(key, out token)) return token;
            int count; counts.TryGetValue(kind, out count); counts[kind] = ++count;
            return tokens[key] = kind + "-" + count;
        }

        private void Learn(string value, string kind)
        {
            if (!string.IsNullOrWhiteSpace(value) && !identities.ContainsKey(value)) identities[value] = Token(value, kind);
        }

        private static bool TryAddress(string text, out string address, out string punctuation)
        {
            address = text;
            punctuation = "";
            IPAddress parsed;
            // A terminal full stop belongs to the sentence, not to IPv6.
            while (!IPAddress.TryParse(address, out parsed) && address.EndsWith(".", StringComparison.Ordinal))
            { address = address.Substring(0, address.Length - 1); punctuation = "." + punctuation; }
            return IPAddress.TryParse(address, out parsed);
        }

        private void LearnProxy(string text)
        {
            Learn(text, "SERVER");
            foreach (var part in Regex.Split(text, @"[;,\s]+"))
            {
                var value = part.Trim();
                var equals = value.IndexOf('=');
                if (equals >= 0) value = value.Substring(equals + 1);
                Uri uri;
                if (Uri.TryCreate(value.Contains("://") ? value : "http://" + value.TrimStart('*', '.'), UriKind.Absolute, out uri)
                    && !string.IsNullOrWhiteSpace(uri.Host)) Learn(uri.Host, "SERVER");
            }
        }

        private void Discover(object value, string path)
        {
            var obj = JsonValue.AsObject(value);
            if (obj != null)
            {
                foreach (var pair in obj)
                {
                    // Address-keyed maps occur in technical data as well as values.
                    DiscoverText(pair.Key);
                    Discover(pair.Value, path + "." + pair.Key);
                }
                return;
            }
            var list = JsonValue.AsList(value);
            if (list != null) { foreach (var item in list) Discover(item, path + "[]"); return; }
            var text = value as string;
            if (text == null) return;
            DiscoverText(text);
            var lower = path.ToLowerInvariant();
            if (lower.EndsWith(".ssid")) Learn(text, "SSID");
            else if (lower.Contains(".networkprofiles[]") && lower.EndsWith(".name")) Learn(text, "NETWORK");
            else if (lower.Contains(".builtin.profiles[]") && (lower.EndsWith(".name") || lower.EndsWith(".friendlyname"))) Learn(text, "VPN");
            else if (lower.EndsWith(".serveraddress") || lower.EndsWith(".proxyserver") || lower.EndsWith(".autoconfigurl") || lower.EndsWith(".pacurl")
                || lower.EndsWith(".proxyoverride") || lower.EndsWith(".bypasslist") || lower.EndsWith(".dohtemplate")
                || lower.EndsWith(".proxy.environment[].value") || (lower.Contains("proxies[]") && lower.EndsWith(".host"))) LearnProxy(text);
            else if ((lower.Contains("suffix") && !lower.EndsWith(".suffixorigin")) || lower.EndsWith(".nrpt[].namespace"))
            { Learn(text, "DNS"); if (text.StartsWith(".", StringComparison.Ordinal)) Learn(text.TrimStart('.'), "DNS"); }
            else if (lower.EndsWith(".computer.name") || lower.EndsWith(".computer.domain") || lower.EndsWith(".computer.workgroup") || lower.EndsWith(".computername") || lower.EndsWith(".hostname")) Learn(text, "HOST");
            else if (lower.EndsWith(".username") || lower.EndsWith(".user")) Learn(text, "USER");
        }

        private void DiscoverText(string text)
        {
            foreach (Match match in Profile.Matches(text)) Learn(match.Groups["profileUser"].Value, "USER");
            foreach (Match match in Mac.Matches(text)) Learn(match.Value, "MAC");
            foreach (Match match in Address.Matches(text))
            {
                string address, punctuation;
                if (TryAddress(match.Value, out address, out punctuation)) Learn(address, "IP");
            }
        }

        private string Replace(string value)
        {
            string whole;
            if (identities.TryGetValue(value, out whole)) return whole;
            return replacements.Replace(value, match =>
            {
                if (match.Groups["profile"].Success)
                    return match.Groups["profilePrefix"].Value + Token(match.Groups["profileUser"].Value, "USER");
                if (match.Groups["mac"].Success) return Token(match.Value, "MAC");
                if (match.Groups["address"].Success)
                {
                    string address, punctuation;
                    return TryAddress(match.Value, out address, out punctuation) ? Token(address, "IP") + punctuation : match.Value;
                }
                return identities[match.Value];
            });
        }

        public object Transform(object value) => TransformValue(value, "");

        private object TransformValue(object value, string path)
        {
            var obj = JsonValue.AsObject(value);
            if (obj != null)
            {
                var result = new Dictionary<string, object>(StringComparer.Ordinal);
                foreach (var pair in obj)
                {
                    IPAddress address;
                    var key = IPAddress.TryParse(pair.Key, out address) && pair.Key.Contains(":") || Address.IsMatch(pair.Key) || Mac.IsMatch(pair.Key) ? Replace(pair.Key) : pair.Key;
                    // Different spellings can canonicalize to the same IP. Keep both
                    // entries rather than silently discarding technical data.
                    var baseKey = key;
                    for (var alias = 2; result.ContainsKey(key); alias++) key = baseKey + "#" + alias;
                    result[key] = pair.Key == "masked" ? (object)true : IsMetadata(pair.Key, path) || IsHardwareLabel(pair.Key, path)
                        ? pair.Value : TransformValue(pair.Value, path + "." + pair.Key);
                }
                return result;
            }
            var list = JsonValue.AsList(value);
            if (list != null) return list.Select(item => TransformValue(item, path + "[]")).ToArray();
            return value is string ? Replace((string)value) : value;
        }

        private static bool IsMetadata(string key, string path) => Metadata.Contains(key) || (path == ".modules[]" && key == "name");

        private static bool IsHardwareLabel(string key, string path) => HardwareLabels.Contains(key) &&
            (path.StartsWith(".modules.hardware.data", StringComparison.Ordinal) || path.StartsWith(".sections.hardware", StringComparison.Ordinal));

        public string SnapshotJson(Snapshot snapshot) => JsonValue.Serialize(Transform(snapshot.Root));
    }
}
