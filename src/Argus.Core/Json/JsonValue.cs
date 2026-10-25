// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Web.Script.Serialization;

namespace Argus.Core.Json
{
    /// <summary>
    /// JSON reading and helpers over the plain object tree JavaScriptSerializer
    /// produces: IDictionary&lt;string, object&gt;, object[], string, bool,
    /// int/long/decimal, null.
    /// </summary>
    public static class JsonValue
    {
        /// <summary>
        /// A serializer without the default limits: MaxJsonLength defaults to
        /// 2,097,152 characters and RecursionLimit to 100, and a snapshot is
        /// already about 1 MB and grows with events and WFP filters.
        /// </summary>
        public static JavaScriptSerializer CreateSerializer()
        {
            return new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 1024 };
        }

        public static object Parse(string json)
        {
            if (json == null) throw new ArgumentNullException(nameof(json));
            return CreateSerializer().DeserializeObject(json);
        }

        public static string Serialize(object value)
        {
            return CreateSerializer().Serialize(value);
        }

        public static IDictionary<string, object> AsObject(object value)
        {
            return value as IDictionary<string, object>;
        }

        /// <summary>Arrays come as object[]; anything enumerable but not a string or an object counts.</summary>
        public static IList<object> AsList(object value)
        {
            if (value == null || value is string || value is IDictionary<string, object>) return null;
            var list = value as IList<object>;
            if (list != null) return list;
            var enumerable = value as IEnumerable;
            if (enumerable == null) return null;
            var result = new List<object>();
            foreach (var item in enumerable) result.Add(item);
            return result;
        }

        public static string AsString(object value)
        {
            return value as string;
        }

        public static bool? AsBool(object value)
        {
            if (value is bool) return (bool)value;
            return null;
        }

        public static bool IsNumber(object value)
        {
            return value is int || value is long || value is decimal || value is double || value is float
                || value is short || value is byte || value is uint || value is ulong || value is ushort || value is sbyte;
        }

        /// <summary>
        /// Numbers come as int, long or decimal depending on their size and
        /// form; comparisons must treat 1 and 1.0 as equal.
        /// </summary>
        public static decimal? AsDecimal(object value)
        {
            if (!IsNumber(value)) return null;
            try { return Convert.ToDecimal(value, CultureInfo.InvariantCulture); }
            catch (OverflowException) { return null; }
        }

        public static int? AsInt(object value)
        {
            var d = AsDecimal(value);
            if (d == null || d != decimal.Truncate(d.Value) || d < int.MinValue || d > int.MaxValue) return null;
            return (int)d.Value;
        }

        /// <summary>Value of a key, or null if the object or the key is missing.</summary>
        public static object Get(object node, string key)
        {
            var obj = AsObject(node);
            object value;
            if (obj == null || key == null || !obj.TryGetValue(key, out value)) return null;
            return value;
        }

        /// <summary>
        /// Resolves a dotted path ("proxy.user.proxyEnable", "routes[0].nextHop").
        /// Returns false if any step is missing: a missing value is not null.
        /// </summary>
        public static bool TryGetPath(object node, string path, out object value)
        {
            value = null;
            if (string.IsNullOrEmpty(path)) { value = node; return true; }
            object current = node;
            foreach (var rawPart in path.Split('.'))
            {
                var part = rawPart;
                int? index = null;
                var bracket = part.IndexOf('[');
                if (bracket >= 0 && part.EndsWith("]", StringComparison.Ordinal))
                {
                    int i;
                    if (!int.TryParse(part.Substring(bracket + 1, part.Length - bracket - 2), NumberStyles.None, CultureInfo.InvariantCulture, out i)) return false;
                    index = i;
                    part = part.Substring(0, bracket);
                }
                if (part.Length > 0)
                {
                    var obj = AsObject(current);
                    object next;
                    if (obj == null || !obj.TryGetValue(part, out next)) return false;
                    current = next;
                }
                if (index != null)
                {
                    var list = AsList(current);
                    if (list == null || index.Value >= list.Count) return false;
                    current = list[index.Value];
                }
            }
            value = current;
            return true;
        }

        /// <summary>Items of an array at a path, or an empty list.</summary>
        public static IList<object> GetList(object node, string path)
        {
            object value;
            if (!TryGetPath(node, path, out value)) return new object[0];
            return AsList(value) ?? new object[0];
        }
    }
}
