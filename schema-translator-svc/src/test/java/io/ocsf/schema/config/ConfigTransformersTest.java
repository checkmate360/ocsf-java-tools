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

package io.ocsf.schema.config;

import io.ocsf.schema.concurrent.ProcessorList;
import io.ocsf.schema.transformers.Transformers;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class ConfigTransformersTest
{

  @Test
  public void load() throws IOException
  {
    final ProcessorList<Transformers> transformers = ConfigTransformers.load("src/test/rules");

    Assert.assertEquals(1, transformers.size());
    Assert.assertEquals(5, transformers.get("XmlWinEventLog").size());
  }
}