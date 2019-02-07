using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

// Copyright (c) 2013 Khalid Abuhakmeh, The MIT License (MIT)
// Source: https://github.com/khalidabuhakmeh/ConsoleTables

// Changes:
//      Restricted values to strings
//      Removed divider from between each row
//      Removed additional formatting logic

namespace ConsoleTables
{
    public class ConsoleTable
    {
        public IList<string> Columns { get; set; }
        public IList<string[]> Rows { get; protected set; }

        public ConsoleTableOptions Options { get; protected set; }

        public ConsoleTable(params string[] columns)
            :this(new ConsoleTableOptions { Columns = new List<string>(columns) })
        {          
        }

        public ConsoleTable(ConsoleTableOptions options)
        {
            Options = options;
            Rows = new List<string[]>();
            Columns = new List<string>(options.Columns);
        }

        public ConsoleTable AddColumn(IEnumerable<string> names)
        {
            foreach (var name in names)
                Columns.Add(name);
            return this;
        }

        public ConsoleTable AddRow(params string[] values)
        {
            if (values == null)
                throw new ArgumentNullException(nameof(values));

            if (!Columns.Any())
                throw new Exception("Please set the columns first");

            if (Columns.Count != values.Length)
                throw new Exception(
                    $"The number columns in the row ({Columns.Count}) does not match the values ({values.Length}");

            Rows.Add(values);
            return this;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();

            // find the longest column by searching each row
            var columnLengths = ColumnLengths();

            // create the string format with padding
            var format = Enumerable.Range(0, Columns.Count)
                .Select(i => " | {" + i + ",-" + columnLengths[i] + "}")
                .Aggregate((s, a) => s + a) + " |";

            // find the longest formatted line
            var maxRowLength = Math.Max(0, Rows.Any() ? Rows.Max(row => string.Format(format, row).Length) : 0);
            var columnHeaders = string.Format(format, Columns.ToArray());

            // longest line is greater of formatted columnHeader and longest row
            var longestLine = Math.Max(maxRowLength, columnHeaders.Length);

            // add each row
            var results = Rows.Select(row => string.Format(format, row)).ToList();

            // create the divider
            var divider = String.Format(" {0} ", new String('-', longestLine - 1));

            builder.AppendLine(divider);
            builder.AppendLine(columnHeaders);
            builder.AppendLine(divider);

            foreach (var row in results)
            {
                //builder.AppendLine(divider);
                builder.AppendLine(row);
            }

            builder.AppendLine(divider);

            return builder.ToString();
        }

        private string Format(List<int> columnLengths, char delimiter = '|')
        {
            var delimiterStr = delimiter == char.MinValue ? string.Empty : delimiter.ToString();
            var format = (Enumerable.Range(0, Columns.Count)
                .Select(i => " "+ delimiterStr + " {" + i + ",-" + columnLengths[i] + "}")
                .Aggregate((s, a) => s + a) + " " + delimiterStr).Trim();
            return format;
        }

        private List<int> ColumnLengths()
        {
            var columnLengths = Columns
                .Select((t, i) => Rows.Select(x => x[i])
                    .Union(new[] { Columns[i] })
                    .Where(x => x != null)
                    .Select(x => x.ToString().Length).Max())
                .ToList();
            return columnLengths;
        }

        public void Write(Format format = ConsoleTables.Format.Default)
        {
            switch (format)
            {
                case ConsoleTables.Format.Default:
                    Console.WriteLine(ToString());
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(format), format, null);
            }
        }

        private static IEnumerable<string> GetColumns<T>()
        {  
            return typeof(T).GetProperties().Select(x => x.Name).ToArray();
        }

        private static object GetColumnValue<T>(object target, string column)
        {
            return typeof(T).GetProperty(column).GetValue(target, null);
        }
    }

    public class ConsoleTableOptions
    {
        public IEnumerable<string> Columns { get; set; } = new List<string>();
        public bool EnableCount { get; set; } = true;
    }

    public enum Format
    {
        Default = 0,
        MarkDown = 1,
        Alternative = 2,
        Minimal = 3
    }
}
