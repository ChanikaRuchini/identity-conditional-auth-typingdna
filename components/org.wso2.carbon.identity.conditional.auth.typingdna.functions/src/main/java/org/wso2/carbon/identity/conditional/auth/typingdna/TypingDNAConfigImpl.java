
/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.typingdna;

import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Governance connector used to configure the parameters need invoke the TypingDNA Authentication.
 */
public class TypingDNAConfigImpl implements IdentityConnectorConfig {

    public static final String ENABLE = "adaptive_authentication.tdna.enable";
    public static final String USERNAME = "adaptive_authentication.tdna.username";
    public static final String CREDENTIAL = "__secret__adaptive_authentication.tdna.password";
    public static final String ADVANCE_MODE_ENABLED = "adaptive_authentication.tdna.advanced.enabled";
    public static final String REGION = "adaptive_authentication.tdna.apiregion";
    public static final String RECEIVER = "adaptive_authentication.tdna.receiver";

    public static final String DEFAULT_ENABLE = "false";
    public static final String DEFAULT_USERNAME = "change-me";
    public static final String DEFAULT_CREDENTIAL = "change-me";
    public static final String DEFAULT_ADVANCE_MODE_ENABLED = "false";
    public static final String DEFAULT_REGION = "eu";
    public static final String DEFAULT_TARGET_HOST = "https://api-";

    @Override
    public String getName() {

        return "typingdna-config";
    }

    @Override
    public String getFriendlyName() {

        return "TypingDNA Configuration";
    }

    @Override
    public String getCategory() {

        return "Other Settings";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 11;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(ENABLE, "Enable TypingDNA");
        mapping.put(USERNAME, "API Key");
        mapping.put(CREDENTIAL, "API Secret");
        mapping.put(ADVANCE_MODE_ENABLED, "Advance TypingDNA-API Mode");
        mapping.put(REGION, "TypingDNA Cloud Region");
        mapping.put(RECEIVER, "Target Host");

        return mapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> mapping = new HashMap<>();

        mapping.put(ENABLE, "Enable TypingDNA Authentication");
        mapping.put(USERNAME, "TypingDNA API Key");
        mapping.put(CREDENTIAL, "TypingDNA API Secret");
        mapping.put(ADVANCE_MODE_ENABLED, "Enable if your TypingDNA account is pro or enterprise");
        mapping.put(REGION, "TypingDNA Cloud Region. (eu /us)");
        mapping.put(RECEIVER, "Target Host");

        return mapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(ENABLE);
        properties.add(USERNAME);
        properties.add(CREDENTIAL);
        properties.add(ADVANCE_MODE_ENABLED);
        properties.add(REGION);
        properties.add(RECEIVER);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(ENABLE, DEFAULT_ENABLE);
        defaultProperties.put(USERNAME, DEFAULT_USERNAME);
        defaultProperties.put(CREDENTIAL, DEFAULT_CREDENTIAL);
        defaultProperties.put(ADVANCE_MODE_ENABLED, DEFAULT_ADVANCE_MODE_ENABLED);
        defaultProperties.put(REGION, DEFAULT_REGION);
        defaultProperties.put(RECEIVER,DEFAULT_TARGET_HOST);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {

        return null;
    }
}
