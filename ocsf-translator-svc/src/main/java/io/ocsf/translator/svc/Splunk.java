/*
 * Copyright (c) 2023 Splunk Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package io.ocsf.translator.svc;

/**
 * The Splunk class defines Splunk attributes available in the raw events.
 */
public final class Splunk
{
  public static final String SOURCE_TYPE     = "sourceType";
  public static final String RAW_EVENT       = "rawEvent";
  public static final String TENANT          = "tenant";
  /**
   * The out-of-band attributes, not available in the raw event data.
   */
  public static final String CUSTOMER_ID     = "customer_uid";
  public static final String CIM_SOURCE_TYPE = "source_type";

  private Splunk() {}
}
