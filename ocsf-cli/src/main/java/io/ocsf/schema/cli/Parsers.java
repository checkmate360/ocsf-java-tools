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

package io.ocsf.schema.cli;

import io.ocsf.utils.Parser;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Manage a map of named parsers.
 * <p>
 * Each parser is registered with a name, by default the name is the source type.
 */
public class Parsers
{
  private static final Logger logger = LoggerFactory.getLogger(Parsers.class);

  private final Map<String, Parser> parsers = new HashMap<>();

  /**
   * Register a new parser using the parser's name.
   *
   * @param parser the parser to be added
   */
  public void register(final Parser parser)
  {
    Objects.requireNonNull(parser, "parser cannot be null");

    register(parser.toString(), parser);
  }

  /**
   * Register a new parser using the given parser name.
   *
   * @param name   the parser name
   * @param parser the parser to be added
   */
  public void register(final String name, final Parser parser)
  {
    Objects.requireNonNull(name, "parser name cannot be null");
    Objects.requireNonNull(parser, "parser cannot be null");

    if (parsers.put(name, parser) != null)
      logger.warn("Parser {} is already registered", name);
  }

  public Parser parser(final String name)
  {
    return parsers.get(name);
  }

  public Collection<Parser> values()
  {
    return Collections.unmodifiableCollection(parsers.values());
  }

}