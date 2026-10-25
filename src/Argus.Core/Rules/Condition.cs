// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using Argus.Core.Facts;
using Argus.Core.Json;

namespace Argus.Core.Rules
{
    /// <summary>
    /// "from" a fact, "where" a predicate holds for an item, "having" a count
    /// of matching items (default: at least one). The language is declarative
    /// and closed: extending it goes through review (D-014). See
    /// docs/schema/rules.md.
    /// </summary>
    public sealed class Condition
    {
        internal Condition(string from, Predicate where, Comparison having)
        {
            From = from;
            Where = where;
            Having = having;
        }

        public string From { get; }
        public Predicate Where { get; }
        public Comparison Having { get; }

        /// <summary>Items of the fact that satisfy "where".</summary>
        public List<FactItem> Match(FactSet fact, EvaluationContext context)
        {
            var result = new List<FactItem>();
            foreach (var item in fact.Items)
            {
                // Only True matches: Unknown (a missing field somewhere) never does.
                if (Where == null || Where.Test(item.Values, context) == Truth.True) result.Add(item);
            }
            return result;
        }

        public bool IsMet(int matchCount, EvaluationContext context)
        {
            return Having == null ? matchCount >= 1 : Having.Test(matchCount, context);
        }
    }

    /// <summary>Values a predicate may need besides the item: thresholds and the snapshot time.</summary>
    public sealed class EvaluationContext
    {
        public EvaluationContext(IReadOnlyDictionary<string, object> thresholds, DateTime nowUtc)
        {
            Thresholds = thresholds ?? new Dictionary<string, object>();
            NowUtc = nowUtc;
        }

        public IReadOnlyDictionary<string, object> Thresholds { get; }
        public DateTime NowUtc { get; }

        /// <summary>"$threshold.name" references a threshold; anything else is a literal.</summary>
        public object Resolve(object value)
        {
            var s = value as string;
            if (s == null || !s.StartsWith("$threshold.", StringComparison.Ordinal)) return value;
            object resolved;
            if (!Thresholds.TryGetValue(s.Substring("$threshold.".Length), out resolved)) throw new RuleFormatException("Unknown threshold " + s + ".");
            return resolved;
        }
    }

    /// <summary>
    /// Three-valued (Kleene) logic: a test of a missing field is Unknown, not
    /// False, so "not" over it stays Unknown instead of matching (D-014:
    /// "unknown" is never "no").
    /// </summary>
    public enum Truth
    {
        False,
        True,
        Unknown,
    }

    public abstract class Predicate
    {
        public abstract Truth Test(IDictionary<string, object> item, EvaluationContext context);

        internal static Truth Of(bool value) => value ? Truth.True : Truth.False;
    }

    /// <summary>Any False gives False; otherwise any Unknown gives Unknown; otherwise True.</summary>
    internal sealed class AllOf : Predicate
    {
        internal AllOf(IReadOnlyList<Predicate> items) { Items = items; }
        internal IReadOnlyList<Predicate> Items { get; }
        public override Truth Test(IDictionary<string, object> item, EvaluationContext context)
        {
            var unknown = false;
            foreach (var p in Items)
            {
                var t = p.Test(item, context);
                if (t == Truth.False) return Truth.False;
                if (t == Truth.Unknown) unknown = true;
            }
            return unknown ? Truth.Unknown : Truth.True;
        }
    }

    /// <summary>Any True gives True; otherwise any Unknown gives Unknown; otherwise False.</summary>
    internal sealed class AnyOf : Predicate
    {
        internal AnyOf(IReadOnlyList<Predicate> items) { Items = items; }
        internal IReadOnlyList<Predicate> Items { get; }
        public override Truth Test(IDictionary<string, object> item, EvaluationContext context)
        {
            var unknown = false;
            foreach (var p in Items)
            {
                var t = p.Test(item, context);
                if (t == Truth.True) return Truth.True;
                if (t == Truth.Unknown) unknown = true;
            }
            return unknown ? Truth.Unknown : Truth.False;
        }
    }

    /// <summary>not Unknown is Unknown.</summary>
    internal sealed class Not : Predicate
    {
        internal Not(Predicate inner) { Inner = inner; }
        internal Predicate Inner { get; }
        public override Truth Test(IDictionary<string, object> item, EvaluationContext context)
        {
            var t = Inner.Test(item, context);
            return t == Truth.Unknown ? Truth.Unknown : (t == Truth.True ? Truth.False : Truth.True);
        }
    }

    /// <summary>
    /// A test of one field. Semantics:
    /// - a missing field or a null value makes every operator Unknown, except
    ///   "exists", which is True or False - "missing" is not "false", and
    ///   "not" over a missing field does not match;
    /// - numbers are compared as decimals (1 equals 1.0);
    /// - strings compare ordinally, ignoring case; "match" is a
    ///   case-insensitive regular expression;
    /// - values of different types are never equal;
    /// - olderThanDays/newerThanDays: an ISO date compared with the snapshot
    ///   time, not the time of analysis.
    /// </summary>
    internal sealed class FieldTest : Predicate
    {
        internal static readonly string[] Operators = { "eq", "ne", "lt", "lte", "gt", "gte", "in", "notIn", "match", "exists", "olderThanDays", "newerThanDays" };

        private readonly Regex _regex;

        internal FieldTest(string path, string op, object operand)
        {
            Path = path;
            Op = op;
            Operand = operand;
            if (op == "match")
            {
                var pattern = operand as string;
                if (pattern == null) throw new RuleFormatException("'match' needs a string pattern.");
                try { _regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200)); }
                catch (ArgumentException e) { throw new RuleFormatException("Invalid 'match' pattern: " + e.Message); }
            }
        }

        internal string Path { get; }
        internal string Op { get; }
        internal object Operand { get; }

        public override Truth Test(IDictionary<string, object> item, EvaluationContext context)
        {
            object value;
            var present = JsonValue.TryGetPath(item, Path, out value) && value != null;
            var operand = context.Resolve(Operand);
            if (Op == "exists") return Of(JsonValue.AsBool(operand) == present);
            if (!present) return Truth.Unknown;
            return Of(TestPresent(value, operand, context));
        }

        private bool TestPresent(object value, object operand, EvaluationContext context)
        {
            switch (Op)
            {
                case "eq": return ValuesEqual(value, operand);
                case "ne": return !ValuesEqual(value, operand);
                case "lt": return Compare(value, operand) < 0;
                case "lte": { var c = Compare(value, operand); return c != null && c <= 0; }
                case "gt": return Compare(value, operand) > 0;
                case "gte": { var c = Compare(value, operand); return c != null && c >= 0; }
                case "in": return (JsonValue.AsList(operand) ?? new object[0]).Any(o => ValuesEqual(value, context.Resolve(o)));
                case "notIn": return !(JsonValue.AsList(operand) ?? new object[0]).Any(o => ValuesEqual(value, context.Resolve(o)));
                case "match": { var s = value as string; return s != null && _regex.IsMatch(s); }
                case "olderThanDays": { var age = AgeDays(value, context); var n = JsonValue.AsDecimal(operand); return age != null && n != null && age.Value > (double)n.Value; }
                case "newerThanDays": { var age = AgeDays(value, context); var n = JsonValue.AsDecimal(operand); return age != null && n != null && age.Value < (double)n.Value; }
                default: throw new RuleFormatException("Unknown operator '" + Op + "'.");
            }
        }

        internal static bool ValuesEqual(object a, object b)
        {
            if (a == null || b == null) return a == null && b == null;
            var da = JsonValue.AsDecimal(a);
            var db = JsonValue.AsDecimal(b);
            if (da != null || db != null) return da != null && db != null && da.Value == db.Value;
            if (a is string && b is string) return string.Equals((string)a, (string)b, StringComparison.OrdinalIgnoreCase);
            if (a is bool && b is bool) return (bool)a == (bool)b;
            return false;
        }

        /// <summary>Order of two numbers or two strings; null if they are not comparable.</summary>
        internal static int? Compare(object a, object b)
        {
            var da = JsonValue.AsDecimal(a);
            var db = JsonValue.AsDecimal(b);
            if (da != null && db != null) return da.Value.CompareTo(db.Value);
            if (a is string && b is string) return string.Compare((string)a, (string)b, StringComparison.OrdinalIgnoreCase);
            return null;
        }

        private static double? AgeDays(object value, EvaluationContext context)
        {
            var s = value as string;
            DateTime date;
            if (s == null || !DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out date)) return null;
            return (context.NowUtc - date).TotalDays;
        }
    }

    /// <summary>A comparison of the match count: {"gte": 2}.</summary>
    public sealed class Comparison
    {
        internal Comparison(string op, object operand)
        {
            Op = op;
            Operand = operand;
        }

        internal string Op { get; }
        internal object Operand { get; }

        public bool Test(int count, EvaluationContext context)
        {
            var n = JsonValue.AsDecimal(context.Resolve(Operand));
            if (n == null) throw new RuleFormatException("'having' needs a number.");
            switch (Op)
            {
                case "eq": return count == n.Value;
                case "ne": return count != n.Value;
                case "lt": return count < n.Value;
                case "lte": return count <= n.Value;
                case "gt": return count > n.Value;
                case "gte": return count >= n.Value;
                default: throw new RuleFormatException("Unknown 'having' operator '" + Op + "'.");
            }
        }
    }

    public sealed class RuleFormatException : Exception
    {
        public RuleFormatException(string message) : base(message) { }
    }
}
