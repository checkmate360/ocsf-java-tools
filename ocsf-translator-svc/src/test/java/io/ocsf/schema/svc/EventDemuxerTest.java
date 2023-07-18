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

package io.ocsf.schema.svc;

import io.ocsf.parser.Parser;
import io.ocsf.schema.Dictionary;
import io.ocsf.schema.Event;
import io.ocsf.schema.RawEvent;
import io.ocsf.schema.Tests;
import io.ocsf.schema.concurrent.BlockingQueue;
import io.ocsf.schema.concurrent.MutableProcessorList;
import io.ocsf.translators.Translators;
import io.ocsf.utils.FMap;
import io.ocsf.utils.Maps;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class EventDemuxerTest extends Tests
{
  private static final String NAME = "syslog";
  private static final String NAME1 = "syslog:1";
  private static final String NAME2 = "syslog:2";

  private static final AtomicBoolean done = new AtomicBoolean();

  // create a very simple "parser"
  private final Parser parser = text -> FMap.<String, Object>b().p(EVENT_ID, Integer.parseInt(text));
  private final Translators translators = new Translators("test");

  private final MutableProcessorList<Parser> parsers = new MutableProcessorList<>(NAME);
  private final MutableProcessorList<Translators> normalizers = new MutableProcessorList<>(NAME);

  private final BlockingQueue<Event> rawEventQueue = new BlockingQueue<>();

  @Before
  public void setUp() throws Exception
  {
    translators.put("Transformer", data ->
        FMap.<String, Object>b()
            .p(EVENT_ID, data.remove(EVENT_ID))
            .p(EVENT_ORIGIN, data.remove(EVENT_ORIGIN))
            .p(Dictionary.RAW_EVENT, data.remove(Dictionary.RAW_EVENT)));

    parsers.register(NAME1, parser);
    normalizers.register(NAME1, translators);

    parsers.register(NAME2, parser);
    normalizers.register(NAME2, translators);

    new Thread(new EventDemuxer(parsers, normalizers, in, out, rawEventQueue)
    {
      @Override
      protected void terminated()
      {
        super.terminated();
        done.set(true);
      }
    }
    ).start();

    // send some data in the input queue
    for (int i = 0; i < MAX_QUEUE_SIZE; i++)
    {
      in.put(new Event(
          FMap.<String, Object>b()
              .p(RawEvent.RAW_EVENT, Integer.toString(i))
              .p(RawEvent.TENANT, "Tenant")
              .p(RawEvent.SOURCE_TYPE, NAME1)));

      in.put(new Event(
          FMap.<String, Object>b()
              .p(RawEvent.RAW_EVENT, Integer.toString(i))
              .p(RawEvent.TENANT, "Tenant")
              .p(RawEvent.SOURCE_TYPE, NAME2)));
    }
  }

  @After
  public void tearDown() throws Exception
  {
    // send 'eos' event to terminate the transformer's thread
    in.put(Event.eos());
  }

  @SuppressWarnings("BusyWait")
  @AfterClass
  public static void afterClass() throws InterruptedException
  {
    for (int i = 0; !done.get() && i < MAX_QUEUE_SIZE; i++)
    {
      Thread.sleep(200);
    }
    Assert.assertTrue(done.get());
  }

  @Test
  public void validate() throws InterruptedException
  {
    for (int i = 0; i < 2 * MAX_QUEUE_SIZE; i++)
    {
      final Map<String, Object> data   = out.take().data();
      final String              source = (String) Maps.getIn(data, new String[]{Dictionary.UNMAPPED, Event.SOURCE_TYPE});

      Assert.assertEquals(5, data.size());
      Assert.assertTrue(NAME1.equals(source) || NAME2.equals(source));
    }

    Assert.assertEquals(0, out.available());
    Assert.assertEquals(0, rawEventQueue.available());
  }

}