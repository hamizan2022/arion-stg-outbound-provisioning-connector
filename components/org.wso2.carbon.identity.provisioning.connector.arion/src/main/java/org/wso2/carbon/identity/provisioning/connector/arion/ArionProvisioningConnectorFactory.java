/*
 *  Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.provisioning.connector.arion;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import java.util.ArrayList;
import java.util.List;

public class ArionProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    private static final Log log = LogFactory.getLog(ArionProvisioningConnectorFactory.class);
    private static final String ARION = "arion";

    @Override
    protected AbstractOutboundProvisioningConnector buildConnector(Property[] provisioningProperties) throws IdentityProvisioningException 
    {
        ArionProvisioningConnector arionConnector = new ArionProvisioningConnector();
        arionConnector.init(provisioningProperties); //setting up the configuration for the connector

        if (log.isDebugEnabled()) {
            log.debug("Arion provisioning connector created successfully.");
        }

        return arionConnector;
    }

    @Override
    public String getConnectorType() {
        return ARION;
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        
        /*
        Property apiVersion = new Property();
        apiVersion.setName(ArionConnectorConstants.PropertyConfig.API_VERSION);
        apiVersion.setDisplayName("API version");
        apiVersion.setRequired(true);
        apiVersion.setType("string");
        apiVersion.setDisplayOrder(1);
        configProperties.add(apiVersion);
        */

        Property domain = new Property();
        domain.setName(ArionConnectorConstants.PropertyConfig.DOMAIN_NAME);
        domain.setDisplayName("Domain Name");
        domain.setRequired(true);
        domain.setType("string");
        domain.setDisplayOrder(1);
        configProperties.add(domain);

        /*
        Property clientId = new Property();
        clientId.setName(ArionConnectorConstants.PropertyConfig.CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setRequired(true);
        clientId.setType("string");
        clientId.setDisplayOrder(3);
        configProperties.add(clientId);
        */

        /*
        Property clientSecret = new Property();
        clientSecret.setName(ArionConnectorConstants.PropertyConfig.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);
        */

        Property username = new Property();
        username.setName(ArionConnectorConstants.PropertyConfig.USERNAME);
        username.setDisplayName("Username");
        username.setRequired(true);
        username.setType("string");
        username.setDisplayOrder(2);
        configProperties.add(username);

        Property password = new Property();
        password.setName(ArionConnectorConstants.PropertyConfig.CLIENT_SECRET);
        password.setDisplayName("Password");
        password.setRequired(true);
        password.setDescription("API Key for Basic Authentication");
        password.setType("string");
//      password.setType("boolean");
//      password.setDefaultValue("true");
        password.setDisplayOrder(3);
        configProperties.add(password);

        /*
        Property tokenEp = new Property();
        tokenEp.setName(ArionConnectorConstants.PropertyConfig.OAUTH2_TOKEN_ENDPOINT);
        tokenEp.setDisplayName("OAuth2 Token Endpoint");
        tokenEp.setRequired(true);
        tokenEp.setType("string");
        tokenEp.setDefaultValue("https://172.16.252.64:8443/oauth2/token");
        tokenEp.setDisplayOrder(4);
        configProperties.add(tokenEp);
        */

        /*
        Property provPattern = new Property();
        provPattern.setName(ArionConnectorConstants.PropertyConfig.PROVISIONING_PATTERN_KEY);
        provPattern.setDisplayName("Provisioning Pattern");
        provPattern.setRequired(false);
        provPattern.setDescription("This pattern is used to build the user id of Salesforce domain. Combination of " +
                "attributes UD (User Domain), UN (Username), TD (Tenant Domain) and IDP (Identity Provider) can be " +
                "used to construct a valid pattern. Ex: {UD, UN, TD, IDP}");
        provPattern.setType("string");
        provPattern.setDisplayOrder(8);
        configProperties.add(provPattern);
        */

        /*
        Property provSeperator = new Property();
        provSeperator.setName(ArionConnectorConstants.PropertyConfig.PROVISIONING_SEPERATOR_KEY);
        provSeperator.setDisplayName("Provisioning Separator");
        provSeperator.setRequired(false);
        provSeperator.setDescription("This is the separator of attributes in Salesforce Outbound Provisioning pattern" +
                ". For example if pattern is {UN,TD} and Username: testUser, Tenant Domain: TestTenant.com, " +
                "Separator:_, Google Domain : testmail.com then the privisioining email is testUser_testTenant" +
                ".com@testmail.com");
        provSeperator.setType("string");
        provSeperator.setDisplayOrder(9);
        configProperties.add(provSeperator);
        */

        /*
        Property provDomain = new Property();
        provDomain.setName(ArionConnectorConstants.PropertyConfig.PROVISIONING_DOMAIN_KEY);
        provDomain.setDisplayName("Provisioning Domain");
        provDomain.setRequired(false);
        provDomain.setType("string");
        provDomain.setDisplayOrder(10);
        configProperties.add(provDomain);
        */

        return configProperties;
    }
}
