// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace Argus.Core.Rules
{
    /// <summary>TZ levels: Критично, Важно, Совет, Инфо.</summary>
    public enum RuleLevel
    {
        Critical,
        Important,
        Advice,
        Info,
    }

    /// <summary>A text in Russian (primary) and English (D-014: rule texts live in the rule JSON).</summary>
    public sealed class LocalizedText
    {
        public LocalizedText(string ru, string en)
        {
            Ru = ru;
            En = en;
        }

        public string Ru { get; }
        public string En { get; }

        /// <summary>English for "en*" cultures, Russian otherwise.</summary>
        public string For(string cultureName)
        {
            return cultureName != null && cultureName.StartsWith("en", StringComparison.OrdinalIgnoreCase) ? En : Ru;
        }
    }

    /// <summary>A detection rule (tunneleye.rule/1): condition over facts, level, thresholds and texts.</summary>
    public sealed class Rule
    {
        public const string Schema = "tunneleye.rule/1";

        internal Rule(string id, RuleLevel level, bool experimental, IReadOnlyList<string> facts,
            IReadOnlyDictionary<string, object> thresholds, Condition condition, IReadOnlyDictionary<string, LocalizedText> text, string sourcePath)
        {
            Id = id;
            Level = level;
            Experimental = experimental;
            Facts = facts;
            Thresholds = thresholds;
            Condition = condition;
            Text = text;
            SourcePath = sourcePath;
        }

        public string Id { get; }
        public RuleLevel Level { get; }
        /// <summary>Not confirmed on the stand: not above Advice, does not affect the overall verdict (D-014).</summary>
        public bool Experimental { get; }
        /// <summary>Facts the rule needs; any unavailable fact makes the rule "not checked".</summary>
        public IReadOnlyList<string> Facts { get; }
        public IReadOnlyDictionary<string, object> Thresholds { get; }
        public Condition Condition { get; }
        /// <summary>title, why, fix and optionally details.</summary>
        public IReadOnlyDictionary<string, LocalizedText> Text { get; }
        public string SourcePath { get; }
    }
}
