// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Argus.Core.Facts;
using Argus.Core.Json;

namespace Argus.Core.Rules
{
    /// <summary>
    /// Reads and validates rules/*.json. A rule with an error is not loaded;
    /// the error is reported (a broken file must not stop the others).
    /// </summary>
    public static class RuleLoader
    {
        private static readonly string[] RequiredTexts = { "title", "why", "fix" };
        private static readonly string[] KnownKeys = { "schema", "id", "level", "experimental", "facts", "thresholds", "condition", "text" };
        private static readonly Regex IdPattern = new Regex("^[a-z][a-z0-9-]*$");

        public sealed class LoadResult
        {
            public List<Rule> Rules { get; } = new List<Rule>();
            public List<string> Errors { get; } = new List<string>();
        }

        public static LoadResult LoadDirectory(string directory, FactCatalog catalog)
        {
            var result = new LoadResult();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var path in Directory.GetFiles(directory, "*.json").OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    var rule = Parse(File.ReadAllText(path, Encoding.UTF8), catalog, path);
                    if (!ids.Add(rule.Id)) throw new RuleFormatException("Duplicate rule id '" + rule.Id + "'.");
                    result.Rules.Add(rule);
                }
                catch (Exception e) when (e is RuleFormatException || e is ArgumentException || e is InvalidOperationException)
                {
                    result.Errors.Add(Path.GetFileName(path) + ": " + e.Message);
                }
            }
            return result;
        }

        public static Rule Parse(string json, FactCatalog catalog, string sourcePath = null)
        {
            var root = JsonValue.AsObject(JsonValue.Parse(json));
            if (root == null) throw new RuleFormatException("A rule must be a JSON object.");
            foreach (var key in root.Keys) if (!KnownKeys.Contains(key)) throw new RuleFormatException("Unknown key '" + key + "'.");
            if (JsonValue.AsString(JsonValue.Get(root, "schema")) != Rule.Schema) throw new RuleFormatException("schema must be " + Rule.Schema + ".");

            var id = JsonValue.AsString(JsonValue.Get(root, "id"));
            if (id == null || !IdPattern.IsMatch(id)) throw new RuleFormatException("id must match " + IdPattern + ".");
            if (sourcePath != null && !string.Equals(Path.GetFileNameWithoutExtension(sourcePath), id, StringComparison.Ordinal))
                throw new RuleFormatException("File name must be the rule id.");

            var level = ParseLevel(JsonValue.AsString(JsonValue.Get(root, "level")));
            var experimental = JsonValue.AsBool(JsonValue.Get(root, "experimental")) == true;
            if (experimental && (level == RuleLevel.Critical || level == RuleLevel.Important))
                throw new RuleFormatException("An experimental rule cannot be above 'advice' (D-014).");

            var facts = JsonValue.GetList(root, "facts").Select(f => f as string).ToList();
            if (facts.Count == 0 || facts.Any(f => f == null)) throw new RuleFormatException("facts must be a non-empty list of names.");
            foreach (var f in facts) if (!catalog.Contains(f)) throw new RuleFormatException("Unknown fact '" + f + "'.");

            var thresholds = new Dictionary<string, object>(StringComparer.Ordinal);
            var thresholdNode = JsonValue.Get(root, "thresholds");
            if (thresholdNode != null)
            {
                var obj = JsonValue.AsObject(thresholdNode);
                if (obj == null) throw new RuleFormatException("thresholds must be an object.");
                foreach (var pair in obj) thresholds[pair.Key] = pair.Value;
            }

            var condition = ParseCondition(JsonValue.AsObject(JsonValue.Get(root, "condition")));
            if (!facts.Contains(condition.From)) throw new RuleFormatException("condition.from must be one of the rule's facts.");
            CheckThresholds(condition, thresholds);

            var text = new Dictionary<string, LocalizedText>(StringComparer.Ordinal);
            var textNode = JsonValue.AsObject(JsonValue.Get(root, "text"));
            if (textNode == null) throw new RuleFormatException("text is required.");
            foreach (var pair in textNode)
            {
                var ru = JsonValue.AsString(JsonValue.Get(pair.Value, "ru"));
                var en = JsonValue.AsString(JsonValue.Get(pair.Value, "en"));
                if (string.IsNullOrWhiteSpace(ru) || string.IsNullOrWhiteSpace(en))
                    throw new RuleFormatException("text." + pair.Key + " needs both 'ru' and 'en' (D-014).");
                text[pair.Key] = new LocalizedText(ru, en);
            }
            foreach (var key in RequiredTexts) if (!text.ContainsKey(key)) throw new RuleFormatException("text." + key + " is required.");

            return new Rule(id, level, experimental, facts, thresholds, condition, text, sourcePath);
        }

        private static RuleLevel ParseLevel(string value)
        {
            switch (value)
            {
                case "critical": return RuleLevel.Critical;
                case "important": return RuleLevel.Important;
                case "advice": return RuleLevel.Advice;
                case "info": return RuleLevel.Info;
                default: throw new RuleFormatException("level must be critical, important, advice or info.");
            }
        }

        internal static Condition ParseCondition(IDictionary<string, object> node)
        {
            if (node == null) throw new RuleFormatException("condition is required.");
            foreach (var key in node.Keys) if (key != "from" && key != "where" && key != "having") throw new RuleFormatException("Unknown condition key '" + key + "'.");
            var from = JsonValue.AsString(JsonValue.Get(node, "from"));
            if (string.IsNullOrEmpty(from)) throw new RuleFormatException("condition.from is required.");
            var whereNode = JsonValue.Get(node, "where");
            var where = whereNode == null ? null : ParsePredicate(whereNode);
            Comparison having = null;
            var havingNode = JsonValue.AsObject(JsonValue.Get(node, "having"));
            if (havingNode != null)
            {
                var count = JsonValue.AsObject(JsonValue.Get(havingNode, "count"));
                if (count == null || count.Count != 1 || havingNode.Count != 1) throw new RuleFormatException("having must be {\"count\": {\"<op>\": n}}.");
                var pair = count.First();
                having = new Comparison(pair.Key, pair.Value);
                if (!new[] { "eq", "ne", "lt", "lte", "gt", "gte" }.Contains(pair.Key)) throw new RuleFormatException("Unknown 'having' operator '" + pair.Key + "'.");
            }
            return new Condition(from, where, having);
        }

        internal static Predicate ParsePredicate(object node)
        {
            var obj = JsonValue.AsObject(node);
            if (obj == null) throw new RuleFormatException("A predicate must be an object.");
            if (obj.ContainsKey("allOf") || obj.ContainsKey("anyOf"))
            {
                if (obj.Count != 1) throw new RuleFormatException("allOf/anyOf must be the only key of its object.");
                var key = obj.ContainsKey("allOf") ? "allOf" : "anyOf";
                var items = JsonValue.AsList(obj[key]);
                if (items == null || items.Count == 0) throw new RuleFormatException(key + " needs a non-empty list.");
                var parsed = items.Select(ParsePredicate).ToList();
                return key == "allOf" ? (Predicate)new AllOf(parsed) : new AnyOf(parsed);
            }
            if (obj.ContainsKey("not"))
            {
                if (obj.Count != 1) throw new RuleFormatException("not must be the only key of its object.");
                return new Not(ParsePredicate(obj["not"]));
            }
            var path = JsonValue.AsString(JsonValue.Get(obj, "path"));
            if (string.IsNullOrEmpty(path)) throw new RuleFormatException("A field test needs 'path'.");
            var ops = obj.Keys.Where(k => k != "path").ToList();
            if (ops.Count != 1) throw new RuleFormatException("A field test needs exactly one operator (path '" + path + "').");
            var op = ops[0];
            if (!FieldTest.Operators.Contains(op)) throw new RuleFormatException("Unknown operator '" + op + "'.");
            var operand = obj[op];
            if ((op == "in" || op == "notIn") && JsonValue.AsList(operand) == null) throw new RuleFormatException("'" + op + "' needs a list.");
            if (op == "exists" && !(operand is bool)) throw new RuleFormatException("'exists' needs true or false.");
            if ((op == "olderThanDays" || op == "newerThanDays") && !JsonValue.IsNumber(operand) && !(operand is string)) throw new RuleFormatException("'" + op + "' needs a number.");
            return new FieldTest(path, op, operand);
        }

        /// <summary>Every "$threshold.x" must name a declared threshold.</summary>
        private static void CheckThresholds(Condition condition, IReadOnlyDictionary<string, object> thresholds)
        {
            var context = new EvaluationContext(thresholds, DateTime.UtcNow);
            if (condition.Having != null) context.Resolve(condition.Having.Operand);
            Visit(condition.Where, context);
        }

        private static void Visit(Predicate p, EvaluationContext context)
        {
            if (p == null) return;
            var all = p as AllOf; if (all != null) { foreach (var i in all.Items) Visit(i, context); return; }
            var any = p as AnyOf; if (any != null) { foreach (var i in any.Items) Visit(i, context); return; }
            var not = p as Not; if (not != null) { Visit(not.Inner, context); return; }
            var test = (FieldTest)p;
            context.Resolve(test.Operand);
            var list = JsonValue.AsList(test.Operand);
            if (list != null) foreach (var o in list) context.Resolve(o);
        }
    }
}
