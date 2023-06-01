/*
 * Copyright 2023 Splunk Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.ocsf.schema.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper function to parse text and number.
 */
public final class Utils
{
  private Utils() {}

  /**
   * Parses the given text as a number. The method supports integer, long, double, and hex numbers.
   *
   * @param str - string representing a number (real, integer, hex notation)
   * @return Number value parsed from str
   * @throws NumberFormatException if the string does not contain a number
   * @see Utils#number(char[], int, int)
   */
  public static final Number number(final String str)
  {
    return number(str.toCharArray(), 0, str.length());
  }

  /**
   * Parses the given text as a number. The method supports integer, long, double, and hex numbers.
   *
   * @param buf    character array of a numeric, real or integer, including hex notation.
   * @param offset start offset into buf
   * @param len    end point into buf (offset + len)
   * @return Number value parsed from buf
   * @throws NumberFormatException if the string does not contain a number
   */
  public static final Number number(final char[] buf, final int offset, final int len)
  {
    if (buf[offset] == '0' && len > 2)
    {
      final int ch = buf[offset + 1];
      if (ch == 'x' || ch == 'X')
      {
        return Integer.valueOf(new String(buf, offset + 2, len - 2), 16);
      }
    }

    final String s = new String(buf, offset, len);
    if (s.indexOf('.') > -1 || s.indexOf('e') > -1 || s.indexOf('E') > -1)
    {
      return Double.valueOf(s);
    }

    return parseNumber(s);
  }

  /**
   * Parses the given text as a whole number. The method supports integer and long numbers.
   *
   * @param s - String representation of an integer or long.
   * @return the parse number
   * @throws NumberFormatException if the string does not contain a number
   */
  @SuppressWarnings("WrapperTypeMayBePrimitive")
  public static final Number parseNumber(final String s)
  {
    final Long N = Long.valueOf(s);
    final int  n = N.intValue();

    // don't use ?: statement, it will break the code!
    if (n == N) return n;

    return N;
  }

  /**
   * Returns the named groups found in the given regex pattern.
   *
   * @param pattern the pattern
   * @return the named groups found in the pattern
   */
  public static List<String> getNamedGroups(final Pattern pattern)
  {
    final List<String> groups  = new ArrayList<>();
    final Matcher      matcher = Pattern.compile("\\(\\?<(.+?)>.*?\\)").matcher(pattern.pattern());

    while (matcher.find())
    {
      for (int i = 1; i <= matcher.groupCount(); ++i)
      {
        groups.add(matcher.group(i));
      }
    }

    return groups;
  }


}
