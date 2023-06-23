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

package io.ocsf.schema.transformers;

import io.ocsf.schema.parsers.InfobloxDHCPParser;
import io.ocsf.utils.Maps;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

public class InfobloxDhcpSyslogTest
{
  private static final String Data = "<30>Sep 28 10:15:46 192.168.1.2 dhcpd[13613]: DHCPACK on 192.168.1.120 to 00:50:56:13:60:56 (C8703420628) via eth1 relay eth1 lease-duration 600 (RENEW) uid 01:00:50:56:13:60:56";
  private static final String RelayData = "<30>May 19 11:30:20 10.160.20.42 dhcpd[10006]: DHCPACK on 10.132.153.40 to 00:10:49:44:2b:22 (p8001049442B22) via eth2 relay 10.132.153.1 lease-duration 43140 (RENEW) uid 01:00:10:49:44:2b:22";

  private static final String Rule = "{" +
      "  \"desc\": \"Translates Infoblox DHCP\"," +
      "" +
      "  \"when\": \"message like 'DHCPACK'\"," +
      "" +
      "  \"parser\": {" +
      "    \"name\": \"message\"," +
      "    \"pattern\": \"DHCPACK on #{ip} to #{mac} (#{hostname}) via #{interface} relay #{relay_interface} lease-duration #{lease_duration} #{_}\"," +
      "    \"output\": \"event_data\"" +
      "  }," +
      "" +
      "  \"rules\": [" +
      "    {" +
      "      \"event_data.ip\": {" +
      "        \"@move\": \"ip\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.mac\": {" +
      "        \"@move\": \"mac\"" +
      "      }" +
      "    }" +
      "  ]" +
      "}";

  private static final String RegexRule = "{" +
      "  \"desc\": \"Translates Infoblox DHCP\"," +
      "" +
      "  \"when\": \"message like 'DHCPACK'\"," +
      "" +
      "  \"parser\": {" +
      "    \"name\": \"message\"," +
      "    \"regex\": \"(?<evcls>DHCPACK)\\\\s+on\\\\s+(?<ip>\\\\S+)\\\\s+to\\\\s+(?<mac>\\\\S+)(?:\\\\s+\\\\((?<host>.+?)\\\\))?\\\\s+via\\\\s+(?<interface>.*)\\\\s+relay\\\\s+(?<relay>\\\\S+)\\\\s+lease-duration\\\\s+(?<duration>\\\\d+).*?(?:uid\\\\s+(?<uid>.+))?\"," +
      "    \"output\": \"event_data\"" +
      "  }," +
      "" +
      "  \"rules\": [" +
      "    {" +
      "      \"event_data.ip\": {" +
      "        \"@move\": \"ip\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.mac\": {" +
      "        \"@move\": \"mac\"" +
      "      }" +
      "    }" +
      "  ]" +
      "}";

  private static final String MultiStageParsingRule = "{" +
      "  \"desc\": \"Translates Infoblox DHCP\"," +
      "" +
      "  \"when\": \"message like 'DHCPACK'\"," +
      "" +
      "  \"parsers\": [{" +
      "    \"name\": \"message\"," +
      "    \"pattern\": \"DHCPACK on #{ip} to #{mac} (#{hostname}) via #{interface} relay #{relay_interface} lease-duration #{lease_duration} #{_}\"," +
      "    \"output\": \"event_data\"" +
      "  }," +
      "  {" +
      "    \"name\": \"event_data.ip\"," +
      "    \"pattern\": \"#{ip1}.#{ip2}.#{ip3}.#{ip4}\"," +
      "    \"output\": \"event_data\"" +
      "  }]," +
      "" +
      "  \"rules\": [" +
      "    {" +
      "      \"event_data.ip\": {" +
      "        \"@move\": \"ip\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.mac\": {" +
      "        \"@move\": \"mac\"" +
      "      }" +
      "    }" +
      "  ]" +
      "}";

  private static final String MultiStageParsingRegex = "{" +
      "  \"desc\": \"Translates Infoblox DHCPACK event.\"," +
      "" +
      "  \"when\": \"message like 'DHCPACK'\"," +
      "" +
      "  \"parsers\": [" +
      "    {" +
      "      \"name\": \"message\"," +
      "      \"regex\": \"(?<refEventName>DHCPACK)\\\\s+on\\\\s+(?<ip>\\\\S+)\\\\s+to\\\\s+(?<mac>\\\\S+)(?:\\\\s+\\\\((?<hostname>.+?)\\\\))?\\\\s+via\\\\s+(?<interface>.*)\\\\s+relay\\\\s+(?<relay>\\\\S+)\\\\s+lease-duration\\\\s+(?<leaseTime>\\\\d+)($|\\\\S+\\\\s\\\\((?<renewal>RENEW)\\\\)\\\\suid\\\\s(?<uid>([A-Za-z0-9]{2}:){6}[A-Za-z0-9]{2}))\"," +
      "      \"output\": \"event_data\"" +
      "    }," +
      "    {" +
      "      \"name\": \"event_data.relay\"," +
      "      \"regex\": \"(?<relayName>10.132.153.1)\"," +
      "      \"output\": \"event_data\"" +
      "    }" +
      "  ]," +
      "" +
      "  \"rules\": [" +
      "    {" +
      "      \"class_uid\": {" +
      "        \"desc\": \"DHCP Activity\"," +
      "        \"@value\": 1020" +
      "      }" +
      "    }," +
      "    {" +
      "      \"disposition_id\": {" +
      "        \"desc\": \"Ack (5)\"," +
      "        \"@value\": 5" +
      "      }" +
      "    }," +
      "    {" +
      "      \"network_interface.type_id\": {" +
      "        \"desc\": \"0 (Unknown)\"," +
      "        \"@value\": 0" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.hostname\": {" +
      "        \"@move\": \"network_interface.hostname\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.interface\": {" +
      "        \"@move\": \"network_interface.name\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.leaseTime\": {" +
      "        \"@move\": {" +
      "          \"name\": \"lease_time\"," +
      "          \"type\": \"integer\"" +
      "        }" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.ip\": {" +
      "        \"@move\": \"network_interface.ip\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.mac\": {" +
      "        \"@move\": \"network_interface.mac\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.uid\": {" +
      "        \"@move\": \"network_interface.uid\"" +
      "      }" +
      "    }," +
      "    {" +
      "      \"relay.type_id\": {" +
      "        \"desc\": \"0 (Unknown)\"," +
      "        \"@value\": 0" +
      "      }" +
      "    }," +
      "    {" +
      "      \"event_data.renewal\": {" +
      "        \"@enum\": {" +
      "          \"name\": \"is_renewal\"," +
      "          \"default\": 0," +
      "          \"values\": {" +
      "            \"RENEW\": 1" +
      "          }" +
      "        }" +
      "      }" +
      "    }" +
      "  ]" +
      "}";

  @Test
  public void parse()
  {
    final InfobloxDHCPParser parser = new InfobloxDHCPParser();

    try
    {
      final Map<String, Object> parsed = parser.parse(Data);
      Assert.assertNotNull(parsed);

      final Map<String, Object> translated = Transformer
          .fromString(Rule)
          .apply(parsed);

      Assert.assertEquals(2, translated.size());
      Assert.assertEquals("192.168.1.120", Maps.getIn(translated, "ip"));
      Assert.assertEquals("00:50:56:13:60:56", Maps.getIn(translated, "mac"));
    }
    catch (final Exception e)
    {
      Assert.fail(e.getMessage());
    }
  }

  @Test
  public void regexParse()
  {
    final InfobloxDHCPParser parser = new InfobloxDHCPParser();

    try
    {
      final Map<String, Object> parsed = parser.parse(Data);
      Assert.assertNotNull(parsed);

      final Map<String, Object> translated = Transformer
          .fromString(RegexRule)
          .apply(parsed);

      Assert.assertEquals(2, translated.size());
      Assert.assertEquals("192.168.1.120", Maps.getIn(translated, "ip"));
      Assert.assertEquals("00:50:56:13:60:56", Maps.getIn(translated, "mac"));
    }
    catch (final Exception e)
    {
      Assert.fail(e.getMessage());
    }
  }
  @Test
  public void multiStageParse()
  {
    final InfobloxDHCPParser parser = new InfobloxDHCPParser();

    try
    {
      final Map<String, Object> parsed = parser.parse(Data);
      Assert.assertNotNull(parsed);

      final Map<String, Object> translated = Transformer
          .fromString(MultiStageParsingRule)
          .apply(parsed);

      Assert.assertEquals(7, parsed.size());
      Assert.assertEquals("192", Maps.getIn(parsed, "event_data.ip1"));
      Assert.assertEquals("168", Maps.getIn(parsed, "event_data.ip2"));
      Assert.assertEquals("1", Maps.getIn(parsed, "event_data.ip3"));
      Assert.assertEquals("120", Maps.getIn(parsed, "event_data.ip4"));

      Assert.assertEquals(2, translated.size());
      Assert.assertEquals("192.168.1.120", Maps.getIn(translated, "ip"));
      Assert.assertEquals("00:50:56:13:60:56", Maps.getIn(translated, "mac"));
    }
    catch (final Exception e)
    {
      Assert.fail(e.getMessage());
    }
  }

  @Test
  public void multiStageRegexParse()
  {
    final InfobloxDHCPParser parser = new InfobloxDHCPParser();

    try
    {
      final Map<String, Object> parsed = parser.parse(RelayData);
      Assert.assertNotNull(parsed);

      final Map<String, Object> translated = Transformer
          .fromString(MultiStageParsingRegex)
          .apply(parsed);

      Assert.assertEquals(7, parsed.size());
      Assert.assertEquals("10.132.153.1", Maps.getIn(parsed, "event_data.relayName"));

      Assert.assertEquals(6, translated.size());
      Assert.assertEquals("10.132.153.40", Maps.getIn(translated, "network_interface.ip"));
      Assert.assertEquals("00:10:49:44:2b:22", Maps.getIn(translated, "network_interface.mac"));
    }
    catch (final Exception e)
    {
      Assert.fail(e.getMessage());
    }
  }

  public static void main(final String ... args)
  {
    System.out.println(MultiStageParsingRule);
  }

}