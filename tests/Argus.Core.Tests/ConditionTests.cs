// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Json;
using Argus.Core.Rules;
using Xunit;

namespace Argus.Core.Tests
{
    public class ConditionTests
    {
        private static readonly DateTime Now = new DateTime(2026, 10, 25, 0, 0, 0, DateTimeKind.Utc);

        private static Truth Eval(string predicateJson, string itemJson, string thresholdsJson = "{}")
        {
            var predicate = RuleLoader.ParsePredicate(JsonValue.Parse(predicateJson));
            var thresholds = new Dictionary<string, object>(JsonValue.AsObject(JsonValue.Parse(thresholdsJson)));
            return predicate.Test(JsonValue.AsObject(JsonValue.Parse(itemJson)), new EvaluationContext(thresholds, Now));
        }

        /// <summary>Whether the item matches: only True does.</summary>
        private static bool Test(string predicateJson, string itemJson, string thresholdsJson = "{}")
        {
            return Eval(predicateJson, itemJson, thresholdsJson) == Truth.True;
        }

        [Fact]
        public void Not_over_a_missing_field_does_not_match()
        {
            Assert.Equal(Truth.Unknown, Eval("{\"not\":{\"path\":\"enabled\",\"eq\":true}}", "{}"));
            Assert.False(Test("{\"not\":{\"path\":\"enabled\",\"eq\":true}}", "{}"));
            Assert.True(Test("{\"not\":{\"path\":\"enabled\",\"eq\":true}}", "{\"enabled\":false}"));
            Assert.Equal(Truth.Unknown, Eval("{\"path\":\"x\",\"eq\":1}", "{\"x\":null}"));
        }

        // T = {"path":"t","eq":true} with t = true; F = with f = false; U = missing field.
        [Theory]
        [InlineData("allOf", "T", "T", Truth.True)]
        [InlineData("allOf", "T", "U", Truth.Unknown)]
        [InlineData("allOf", "F", "U", Truth.False)]
        [InlineData("allOf", "U", "U", Truth.Unknown)]
        [InlineData("anyOf", "F", "F", Truth.False)]
        [InlineData("anyOf", "F", "U", Truth.Unknown)]
        [InlineData("anyOf", "T", "U", Truth.True)]
        [InlineData("anyOf", "U", "U", Truth.Unknown)]
        public void Kleene_truth_table(string combinator, string a, string b, Truth expected)
        {
            System.Func<string, string> p = v => v == "T" ? "{\"path\":\"t\",\"eq\":true}" : v == "F" ? "{\"path\":\"t\",\"eq\":false}" : "{\"path\":\"missing\",\"eq\":true}";
            var json = "{\"" + combinator + "\":[" + p(a) + "," + p(b) + "]}";
            Assert.Equal(expected, Eval(json, "{\"t\":true}"));
        }

        [Theory]
        [InlineData("{\"path\":\"n\",\"eq\":1}", "{\"n\":1.0}", true)]
        [InlineData("{\"path\":\"n\",\"eq\":1}", "{\"n\":10000000000}", false)]
        [InlineData("{\"path\":\"s\",\"eq\":\"Up\"}", "{\"s\":\"up\"}", true)]
        [InlineData("{\"path\":\"s\",\"eq\":1}", "{\"s\":\"1\"}", false)]
        [InlineData("{\"path\":\"b\",\"eq\":false}", "{\"b\":false}", true)]
        [InlineData("{\"path\":\"b\",\"ne\":true}", "{\"b\":false}", true)]
        [InlineData("{\"path\":\"n\",\"lt\":5}", "{\"n\":4.5}", true)]
        [InlineData("{\"path\":\"n\",\"lte\":5}", "{\"n\":5}", true)]
        [InlineData("{\"path\":\"n\",\"gt\":5}", "{\"n\":5}", false)]
        [InlineData("{\"path\":\"n\",\"gte\":5}", "{\"n\":5.0}", true)]
        [InlineData("{\"path\":\"s\",\"in\":[\"refused\",\"timeout\"]}", "{\"s\":\"timeout\"}", true)]
        [InlineData("{\"path\":\"s\",\"notIn\":[\"refused\",\"timeout\"]}", "{\"s\":\"open\"}", true)]
        [InlineData("{\"path\":\"s\",\"match\":\"^tap-\"}", "{\"s\":\"TAP-Windows\"}", true)]
        [InlineData("{\"path\":\"a.b\",\"eq\":2}", "{\"a\":{\"b\":2}}", true)]
        public void Field_operators(string predicate, string item, bool expected)
        {
            Assert.Equal(expected, Test(predicate, item));
        }

        [Theory]
        [InlineData("{\"path\":\"x\",\"eq\":false}")]
        [InlineData("{\"path\":\"x\",\"ne\":true}")]
        [InlineData("{\"path\":\"x\",\"lt\":5}")]
        [InlineData("{\"path\":\"x\",\"notIn\":[1]}")]
        [InlineData("{\"path\":\"x\",\"match\":\".*\"}")]
        public void A_missing_field_fails_every_operator(string predicate)
        {
            Assert.Equal(Truth.Unknown, Eval(predicate, "{}"));
            Assert.Equal(Truth.Unknown, Eval(predicate, "{\"x\":null}"));
        }

        [Fact]
        public void Exists_tells_missing_and_null_from_present()
        {
            Assert.True(Test("{\"path\":\"x\",\"exists\":false}", "{}"));
            Assert.True(Test("{\"path\":\"x\",\"exists\":false}", "{\"x\":null}"));
            Assert.False(Test("{\"path\":\"x\",\"exists\":false}", "{\"x\":false}"));
            Assert.True(Test("{\"path\":\"x\",\"exists\":true}", "{\"x\":0}"));
        }

        [Fact]
        public void Dates_are_compared_with_the_snapshot_time()
        {
            Assert.True(Test("{\"path\":\"d\",\"olderThanDays\":1095}", "{\"d\":\"2020-01-01\"}"));
            Assert.False(Test("{\"path\":\"d\",\"olderThanDays\":1095}", "{\"d\":\"2025-06-01\"}"));
            Assert.True(Test("{\"path\":\"d\",\"newerThanDays\":30}", "{\"d\":\"2026-10-20T12:00:00Z\"}"));
            Assert.False(Test("{\"path\":\"d\",\"olderThanDays\":1}", "{\"d\":\"not a date\"}"));
        }

        [Fact]
        public void Combinators_and_thresholds()
        {
            const string p = "{\"allOf\":[{\"path\":\"g\",\"gte\":2},{\"anyOf\":[{\"path\":\"m\",\"exists\":false},{\"path\":\"m\",\"lte\":\"$threshold.max\"}]},{\"not\":{\"path\":\"t\",\"eq\":true}}]}";
            Assert.True(Test(p, "{\"g\":2,\"m\":5,\"t\":false}", "{\"max\":20}"));
            Assert.True(Test(p, "{\"g\":2,\"t\":false}", "{\"max\":20}"));
            Assert.False(Test(p, "{\"g\":2,\"m\":50,\"t\":false}", "{\"max\":20}"));
            Assert.False(Test(p, "{\"g\":2,\"m\":5,\"t\":true}", "{\"max\":20}"));
        }

        [Theory]
        [InlineData("{\"path\":\"x\",\"between\":1}")]
        [InlineData("{\"path\":\"x\",\"eq\":1,\"ne\":2}")]
        [InlineData("{\"eq\":1}")]
        [InlineData("{\"path\":\"x\",\"in\":1}")]
        [InlineData("{\"path\":\"x\",\"exists\":\"yes\"}")]
        [InlineData("{\"path\":\"x\",\"match\":\"(\"}")]
        [InlineData("{\"allOf\":[]}")]
        [InlineData("{\"allOf\":[{\"path\":\"x\",\"eq\":1}],\"path\":\"y\"}")]
        public void Rejects_malformed_predicates(string predicate)
        {
            Assert.Throws<RuleFormatException>(() => RuleLoader.ParsePredicate(JsonValue.Parse(predicate)));
        }
    }
}
