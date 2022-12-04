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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.ProvisionedIdentifier;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.net.ssl.SSLContext;

public class ArionProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final long serialVersionUID = 8465869197181038416L;

    private static final Log log = LogFactory.getLog(ArionProvisioningConnector.class);
    private ArionProvisioningConnectorConfig configHolder;

    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property.getName()) && "1"
                        .equals(property.getValue())) {
                    jitProvisioningEnabled = true;
                }
            }
        }

        configHolder = new ArionProvisioningConnectorConfig(configs);
    }

    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {
        String provisionedId = null;

        if (provisioningEntity != null) {

            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for Salesforce connector");
                return null;
            }

            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) 
            {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    try {
						provisionedId = createUser(provisioningEntity);
					} catch (IdentityProvisioningException | KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
						log.warn("Error during createUser(): "+e.toString());
					} 
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
//                  update(provisioningEntity.getIdentifier().getIdentifier(), buildJsonObject(provisioningEntity)); //hamizan remarked
                	updateUser(provisioningEntity);
                } else {
                    log.warn("Unsupported provisioning operation 1.");
                }
            } 
            else if(provisioningEntity.getEntityType() == ProvisioningEntityType.GROUP) 
            {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteRole(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    try {
						provisionedId = createRole(provisioningEntity);
					} catch (IdentityProvisioningException | KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
						log.warn("Error during createRole(): "+e.toString());
					} 
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                	updateRole(provisioningEntity);
                } else {
                    log.warn("Unsupported provisioning operation 1.");
                }
            }
            else {
                log.warn("Unsupported provisioning operation 2.");
            }
        }else {
        	log.warn("Unsupported provisioning operation 3.");
        }

        // creates a provisioned identifier for the provisioned user.
        ProvisionedIdentifier identifier = new ProvisionedIdentifier();
        identifier.setIdentifier(provisionedId);
        return identifier;
    }

    /**
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private JSONObject buildJsonObject(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String provisioningPattern = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.PROVISIONING_PATTERN_KEY);
        if (StringUtils.isBlank(provisioningPattern)) {
            log.info("Provisioning pattern is not defined, hence using default provisioning pattern");
            provisioningPattern = ArionConnectorConstants.PropertyConfig.DEFAULT_PROVISIONING_PATTERN;
        }
        String provisioningSeparator = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.PROVISIONING_SEPERATOR_KEY);
        if (StringUtils.isBlank(provisioningSeparator)) {
            log.info("Provisioning separator is not defined, hence using default provisioning separator");
            provisioningSeparator = ArionConnectorConstants.PropertyConfig.DEFAULT_PROVISIONING_SEPERATOR;
        }
        String idpName = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.IDP_NAME_KEY);

        JSONObject user = new JSONObject();

        try {
            /**
             * Mandatory properties : 12 and this will vary according to API Version
             *
             * Alias, Email, EmailEncodingKey, LanguageLocaleKey, LastName, LocaleSidKey, ProfileId,
             * TimeZoneSidKey, User-name, UserPermissionsCallCenterAutoLogin,
             * UserPermissionsMarketingUser, UserPermissionsOfflineUser
             **/

            Map<String, String> requiredAttributes = getSingleValuedClaims(provisioningEntity.getAttributes());

            String userIdClaimURL = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.USER_ID_CLAIM_URI_KEY);
            String provisioningDomain = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.PROVISIONING_DOMAIN_KEY);
            String userId = provisioningEntity.getEntityName();

            if (StringUtils.isNotBlank(requiredAttributes.get(userIdClaimURL))) {
                userId = requiredAttributes.get(userIdClaimURL);
            }

            String userIdFromPattern = null;

            if (provisioningPattern != null) {
                userIdFromPattern = buildUserId(provisioningEntity, provisioningPattern, provisioningSeparator,idpName);
            }
            if (StringUtils.isNotBlank(userIdFromPattern)) {
                userId = userIdFromPattern;
            }

            if (StringUtils.isBlank(userId)) {
                throw new IdentityProvisioningException("Cannot Find Username Attribute for Provisioning");
            }
            
            if (isDebugEnabled) {
                log.debug("1. hamizan testing user id::" + userId);
            }

            if (StringUtils.isNotBlank(provisioningDomain) && !userId.endsWith(provisioningDomain)) {
                userId = userId.replaceAll("@", ".").concat("@").concat(provisioningDomain);
            }
            
            if (isDebugEnabled) {
                log.debug("2. hamizan testing user id::" + userId);
            }
            
            requiredAttributes.put(ArionConnectorConstants.USERNAME_ATTRIBUTE, userId);

            Iterator<Entry<String, String>> iterator = requiredAttributes.entrySet().iterator();

            while (iterator.hasNext()) {
                Map.Entry<String, String> mapEntry = iterator.next();
                if ("true".equals(mapEntry.getValue())) {
                    user.put(mapEntry.getKey(), true);
                } else if ("false".equals(mapEntry.getValue())) {
                    user.put(mapEntry.getKey(), false);
                } else {
                    user.put(mapEntry.getKey(), mapEntry.getValue());
                }
                if (isDebugEnabled) {
                    log.debug("The key is: " + mapEntry.getKey() + " , value is: " + mapEntry.getValue());
                }
            }

            if (isDebugEnabled) {
                log.debug("JSON object of User\n" + user.toString(2));
            }

        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
        
        if (isDebugEnabled) {
        	log.debug("Hamizan checking user JSON: " + user);
            log.debug("Hamizan checking user JSON toString: " + user.toString());
        }

        return user;
    }
    
    /**
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private JSONObject buildJsonObject_Role(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException { //hamizan - currently no use

        boolean isDebugEnabled = log.isDebugEnabled(); 

        String provisioningPattern = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.PROVISIONING_PATTERN_KEY);
        if (StringUtils.isBlank(provisioningPattern)) {
            log.info("Provisioning pattern is not defined, hence using default provisioning pattern");
            provisioningPattern = ArionConnectorConstants.PropertyConfig.DEFAULT_PROVISIONING_PATTERN;
        }
        String provisioningSeparator = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.PROVISIONING_SEPERATOR_KEY);
        if (StringUtils.isBlank(provisioningSeparator)) {
            log.info("Provisioning separator is not defined, hence using default provisioning separator");
            provisioningSeparator = ArionConnectorConstants.PropertyConfig.DEFAULT_PROVISIONING_SEPERATOR;
        }
        String idpName = this.configHolder.getValue(ArionConnectorConstants.PropertyConfig.IDP_NAME_KEY);

        JSONObject user = new JSONObject();

        try {

            Map<String, String> requiredAttributes = getSingleValuedClaims(provisioningEntity.getAttributes());

            String userId = provisioningEntity.getEntityName();

            if (StringUtils.isBlank(userId)) {
                throw new IdentityProvisioningException("Cannot Find role name Attribute for Provisioning");
            }
            
            requiredAttributes.put(ArionConnectorConstants.NEW_ROLE_NAME, userId);
            
            Iterator<Entry<String, String>> iterator = requiredAttributes.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, String> mapEntry = iterator.next();
                if ("true".equals(mapEntry.getValue())) {
                    user.put(mapEntry.getKey(), true);
                } else if ("false".equals(mapEntry.getValue())) {
                    user.put(mapEntry.getKey(), false);
                } else {
                    user.put(mapEntry.getKey(), mapEntry.getValue());
                }
                if (isDebugEnabled) {
                    log.debug("The key is: " + mapEntry.getKey() + " , value is: " + mapEntry.getValue());
                }
            }


            if (isDebugEnabled) {
                log.debug("JSON object of User\n" + user.toString(2));
            }

        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
        
        if (isDebugEnabled) {
        	log.debug("Hamizan checking user JSON: " + user);
            log.debug("Hamizan checking user JSON toString: " + user.toString());
        }

        return user;
    }
    
    @Override
    protected Map<String, String> getSingleValuedClaims(Map<ClaimMapping, List<String>> attributeMap) {

        Map<String, String> claimValues = new HashMap<>();

        for (Map.Entry<ClaimMapping, List<String>> entry : attributeMap.entrySet()) {
            ClaimMapping mapping = entry.getKey();
            if (mapping.getRemoteClaim() != null && mapping.getRemoteClaim().getClaimUri() != null) {
                String claimUri = mapping.getRemoteClaim().getClaimUri();
                
                log.debug("---hamizan checking claimUri===>"+claimUri);

                if (!(IdentityProvisioningConstants.GROUP_CLAIM_URI.equals(claimUri)
                        || IdentityProvisioningConstants.PASSWORD_CLAIM_URI.equals(claimUri) || IdentityProvisioningConstants.USERNAME_CLAIM_URI
                        .equals(claimUri))) {
                    if (entry.getValue() != null && entry.getValue().get(0) != null) {
                    	log.debug("------hamizan checking claim (1) value::"+entry.getValue().get(0));
                        claimValues.put(claimUri, entry.getValue().get(0));
                    } else {
                    	log.debug("------hamizan checking claim (2) value::"+entry.getValue().get(0));
                        claimValues.put(claimUri, mapping.getDefaultValue());
                    }
                }
            }
        }

        return claimValues;
    }

    /**
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     * @throws KeyStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyManagementException 
     */
    private String createUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String provisionedId = null;
        int i=0;
        
        //FOR TESTING ONLY TO BYPASS THE SSL 
        /*
        SSLContextBuilder builder = new SSLContextBuilder();
        builder.loadTrustMaterial(null, new TrustStrategy() {
             public boolean isTrusted(final X509Certificate[] chain, String authType) throws CertificateException {
                  return true;
             }
        });
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
        */
        
        /*
        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext,SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        */
        
        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build())   
//      try (CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build()) //bypass ssl 
        {
            JSONObject user = buildJsonObject(provisioningEntity);

//          HttpPost post = new HttpPost(this.getUserObjectEndpoint()); //hamizan remarked
            HttpPost post = new HttpPost(this.getUserObjectEndpoint()+"userCreate");
            setAuthorizationHeader(post); 

            if(post.getURI()!=null)
            	log.debug("Hamizan checking post getURI(): " + post.getURI().toString());
            if(post.getRequestLine()!=null)
            	log.debug("Hamizan checking post getRequestLine(): " + post.getRequestLine().toString());
            if(post.getConfig()!=null)
            	log.debug("Hamizan checking post getConfig(): " + post.getConfig().toString());

            post.setEntity(new StringEntity(user.toString(),ContentType.create(ArionConnectorConstants.CONTENT_TYPE_APPLICATION_JSON)));

            try (CloseableHttpResponse response = httpclient.execute(post)) { 

            	/*
                InputStream is = response.getEntity().getContent();
                BufferedReader rd = new BufferedReader(new InputStreamReader(is));
                String line;
                while ((line = rd.readLine()) != null) { 
                	log.debug("Hamizan checking SSL ERROR: " + line);
                }
                */
            	
            	log.debug("--hamizan testing entity name::"+provisioningEntity.getEntityName());
            	log.debug("--hamizan testing entity type::"+provisioningEntity.getEntityType().toString());
				/*
				 * if(provisioningEntity.getIdentifier()!=null)
				 * log.debug("--hamizan testing id::"+provisioningEntity.getIdentifier().
				 * getIdentifier());
				 */
            	log.debug("--hamizan testing counter::"+String.valueOf(++i));

                if (isDebugEnabled) {
                    log.debug("HTTP status " + response.getStatusLine().getStatusCode() + " creating user. ("+HttpStatus.SC_OK+")");
                }

                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Create response: " + jsonResponse.toString(2));
                    }

//                  if (jsonResponse.getBoolean("success")) { //hamizan-remarked
//                      provisionedId = jsonResponse.getString("id"); //hamizan-remarked
                    	provisionedId = jsonResponse.getString("message");
                    	if(!provisionedId.isEmpty())
                    		provisionedId = provisionedId.replaceAll("id=", "");
                        if (isDebugEnabled) {
                            log.debug("(SUCCESS) New record id::(" + provisionedId+")");
                        }
//                  }
                } else {
                	JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: " + response.getStatusLine().getReasonPhrase());
                    if (isDebugEnabled) {
                        log.debug("Error response 1: " + readResponse(post)); 
                        log.debug("Error response 2: " + jsonResponse.toString(2)); 
                    }
                }
            } catch (IOException | JSONException e) {
            	log.error("Hamizan testing ERROR Provisioning, line:: "+e.toString());
                throw new IdentityProvisioningException("Error in invoking provisioning operation for the user", e);
            } finally {
                post.releaseConnection();
            }

            if (isDebugEnabled) {
                log.debug("Returning created user's ID: " + provisionedId);
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }
        return provisionedId;
    }
    
    /**
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     * @throws KeyStoreException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyManagementException 
     */
    private String createRole(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException {  //hamizan added on 28/10/2022

        boolean isDebugEnabled = log.isDebugEnabled();

        String provisionedId = null;
        int i=0;
        
        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build())   
        {
            //JSONObject user = buildJsonObject_Role(provisioningEntity);
        	JSONObject user = new JSONObject();
        	user.put(ArionConnectorConstants.ROLE_NAME, provisioningEntity.getEntityName()); 
        	
            if (isDebugEnabled) {
                log.debug("Hamizan checking JSON object of User\n" + user.toString(2));
            }

            HttpPost post = new HttpPost(this.getUserObjectEndpoint()+"userGroupCreate");
            setAuthorizationHeader(post); 

            if(post.getURI()!=null)
            	log.debug("Hamizan checking post getURI(): " + post.getURI().toString());
            if(post.getRequestLine()!=null)
            	log.debug("Hamizan checking post getRequestLine(): " + post.getRequestLine().toString());
            if(post.getConfig()!=null)
            	log.debug("Hamizan checking post getConfig(): " + post.getConfig().toString());

            post.setEntity(new StringEntity(user.toString(),ContentType.create(ArionConnectorConstants.CONTENT_TYPE_APPLICATION_JSON)));

            try (CloseableHttpResponse response = httpclient.execute(post)) { 
            	
            	log.debug("--hamizan testing entity name::"+provisioningEntity.getEntityName());
            	log.debug("--hamizan testing entity type::"+provisioningEntity.getEntityType().toString());
            	log.debug("--hamizan testing counter::"+String.valueOf(++i));

                if (isDebugEnabled) {
                    log.debug("HTTP status " + response.getStatusLine().getStatusCode() + " creating role. ("+HttpStatus.SC_OK+")");
                }

                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Create response: " + jsonResponse.toString(2));
                    }

//                  if (jsonResponse.getBoolean("success")) { //hamizan-remarked
//                      provisionedId = jsonResponse.getString("id"); //hamizan-remarked
                    	provisionedId = jsonResponse.getString("message");
                    	if(!provisionedId.isEmpty())
                    		//provisionedId = provisionedId.replaceAll("id=", "");
                    		provisionedId = provisionedId.substring(provisionedId.indexOf("=")+1,provisionedId.indexOf(" "));
                        if (isDebugEnabled) {
                            log.debug("(SUCCESS) New record id::(" + provisionedId+")");
                        }
//                  }
                } else {
                	JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: " + response.getStatusLine().getReasonPhrase());
                    if (isDebugEnabled) {
                        log.debug("Error response 1: " + readResponse(post)); 
                        log.debug("Error response 2: " + jsonResponse.toString(2)); 
                    }
                }
            } catch (IOException | JSONException e) {
            	log.error("Hamizan testing ERROR Provisioning, line:: "+e.toString());
                throw new IdentityProvisioningException("Error in invoking provisioning operation for the role", e);
            } finally {
                post.releaseConnection();
            }

            if (isDebugEnabled) {
                log.debug("Returning created user's ID: " + provisionedId);
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }
        return provisionedId;
    }

    private String readResponse(HttpPost post) throws IOException {
        try (InputStream is = post.getEntity().getContent()) {
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuilder response = new StringBuilder();
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            rd.close();
            return response.toString();
        }
    }

    /**
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        JSONObject entity = new JSONObject();
        try {
        	/* hamizan remarked on 28/10/2022
            entity.put(ArionConnectorConstants.IS_ACTIVE, false);
            entity.put(ArionConnectorConstants.USERNAME_ATTRIBUTE, alterUsername(provisioningEntity));
            */
        	
        	entity.put(ArionConnectorConstants.PropertyConfig.PROVISIONED_USER_ID_PARAM, provisioningEntity.getIdentifier().getIdentifier()); //hamizan added on 28/10/2022
            update(provisioningEntity.getIdentifier().getIdentifier(), entity, "userDelete");
        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
    }
    
    /** hamizan added function to update the user 29/10/2022
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void deleteRole(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        JSONObject entity = new JSONObject();
        try {
        	entity.put(ArionConnectorConstants.PropertyConfig.PROVISIONED_USER_ID_PARAM, provisioningEntity.getIdentifier().getIdentifier()); //hamizan added on 28/10/2022
            update(provisioningEntity.getIdentifier().getIdentifier(), entity, "userGroupDelete");
        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
    }
    
    /** hamizan added function to update the user 29/10/2022
     * @param provisioningEntity
     * @throws IdentityProvisioningException
     */
    private void updateUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        JSONObject entity = new JSONObject();
        entity = buildJsonObject(provisioningEntity);
        try {
        	entity.put(ArionConnectorConstants.PropertyConfig.PROVISIONED_USER_ID_PARAM, provisioningEntity.getIdentifier().getIdentifier()); //hamizan added on 28/10/2022
        	update(provisioningEntity.getIdentifier().getIdentifier(), entity,"userUpdate"); 
        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
    }
    
    private void updateRole(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException { //hamizan added on 28/10/2022

        JSONObject entity = new JSONObject();
        boolean isDebugEnabled = log.isDebugEnabled();
        
        //entity = buildJsonObject_Role(provisioningEntity);
        try {
        	entity.put(ArionConnectorConstants.PropertyConfig.PROVISIONED_USER_ID_PARAM, provisioningEntity.getIdentifier().getIdentifier()); 
        	entity.put(ArionConnectorConstants.NEW_ROLE_NAME, provisioningEntity.getEntityName()); 
            if (isDebugEnabled) {
                log.debug("Hamizan checking JSON object of User\n" + entity.toString(2));
            }
            
        	update(provisioningEntity.getIdentifier().getIdentifier(), entity,"userGroupUpdate"); 
        } catch (JSONException e) {
            log.error("Error while creating JSON body");
            throw new IdentityProvisioningException(e);
        }
    }

    /**
     * @param provsionedId
     * @param entity
     * @param api Name //Hamizan added 29/10/2022
     * @return
     * @throws IdentityProvisioningException
     */
    private void update(String provsionedId, JSONObject entity, String apiName) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        /*
        HttpPost patch = new HttpPost(this.getUserObjectEndpoint() + provsionedId) {
            @Override
            public String getMethod() {
                return "PATCH";
            }
        };
        */

        HttpPost patch = new HttpPost(this.getUserObjectEndpoint() + apiName); 
        
        if(patch.getURI()!=null)
        	log.debug("Hamizan checking post getURI(): " + patch.getURI().toString());
        if(patch.getRequestLine()!=null)
        	log.debug("Hamizan checking post getRequestLine(): " + patch.getRequestLine().toString());
        if(patch.getConfig()!=null)
        	log.debug("Hamizan checking post getConfig(): " + patch.getConfig().toString());
        		
        setAuthorizationHeader(patch);
        
        if (isDebugEnabled) {
            log.debug("JSON object \n" + entity.toString(2));
        }
        
        patch.setEntity(new StringEntity(entity.toString(),ContentType.create(ArionConnectorConstants.CONTENT_TYPE_APPLICATION_JSON)));

        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {
            try (CloseableHttpResponse response = httpclient.execute(patch)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK || response.getStatusLine().getStatusCode() == HttpStatus.SC_NO_CONTENT) {
                    if (isDebugEnabled) {
                        log.debug("HTTP status " + response.getStatusLine().getStatusCode() + " updating user " + provsionedId + "\n\n");
                    }
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: " + response.getStatusLine().getStatusCode());
                    if (isDebugEnabled) {
                        log.debug("Error response: " + readResponse(patch));
                    }
                }
            } catch (IOException e) {
                log.error("Error in invoking provisioning request");
                throw new IdentityProvisioningException(e);
            }

        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        } finally {
            patch.releaseConnection();
        }

    }

    /**
     * adding OAuth authorization headers to a httpMethod
     *
     * @param httpMethod method which wants to add Authorization header
     */
    private void setAuthorizationHeader(HttpRequestBase httpMethod) throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

//      String accessToken = authenticate(); //hamizan-remarked this line because this one is salesforce authentication to get the token
        String accessToken = authenticateArionStargate(); //hamizan-this is actually not a token. it is an api key taken from the screen that is entered by aurora user or admin
        String apiUser = getApiUser();
        if (StringUtils.isNotBlank(accessToken)) {
            httpMethod.addHeader(ArionConnectorConstants.AUTHORIZATION_HEADER_NAME,this.getBasicAuthenticationHeader(apiUser,accessToken));

            if (isDebugEnabled) {
                log.debug("Setting authorization header for method: " + httpMethod.getMethod() + " as follows,");
                Header authorizationHeader = httpMethod.getLastHeader(ArionConnectorConstants.AUTHORIZATION_HEADER_NAME);
                log.debug(authorizationHeader.getName() + ": " + authorizationHeader.getValue());
            }
        } else {
            throw new IdentityProvisioningException("Authentication failed");
        }

    }
    
    //hamizan-for arion stargate basic authenticator
    private static final String getBasicAuthenticationHeader(String username, String password) {
        String valueToEncode = username + ":" + password;
        return ArionConnectorConstants.AUTHORIZATION_HEADER_BASIC + " " + Base64.getEncoder().encodeToString(valueToEncode.getBytes());
    }

    /**
     * authenticate to salesforce API.
     */
    private String authenticate() throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {

            String url = configHolder.getValue(ArionConnectorConstants.PropertyConfig.OAUTH2_TOKEN_ENDPOINT);
            if (isDebugEnabled) {
            	log.debug("Hamizan checking url in authenticate(): " + url);
            }

//          HttpPost post = new HttpPost(StringUtils.isNotBlank(url) ? url : IdentityApplicationConstants.GOOGLE_TOKEN_URL); //temp remarked
            HttpPost post = new HttpPost();

            List<BasicNameValuePair> params = new ArrayList<>();

            params.add(new BasicNameValuePair(ArionConnectorConstants.CLIENT_ID,configHolder.getValue(ArionConnectorConstants.PropertyConfig.CLIENT_ID)));
            params.add(new BasicNameValuePair(ArionConnectorConstants.CLIENT_SECRET,configHolder.getValue(ArionConnectorConstants.PropertyConfig.CLIENT_SECRET)));
            params.add(new BasicNameValuePair(ArionConnectorConstants.PASSWORD,configHolder.getValue(ArionConnectorConstants.PropertyConfig.PASSWORD)));
            params.add(new BasicNameValuePair(ArionConnectorConstants.GRANT_TYPE,ArionConnectorConstants.GRANT_TYPE_PASSWORD));
            params.add(new BasicNameValuePair(ArionConnectorConstants.USERNAME,configHolder.getValue(ArionConnectorConstants.PropertyConfig.USERNAME)));

            post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            try (CloseableHttpResponse response = httpclient.execute(post)) {
                // send the request

                if (isDebugEnabled) {
                    log.debug("Authentication to salesforce returned with response code: " + response.getStatusLine().getStatusCode());
                }

                sb.append("HTTP status " + response.getStatusLine().getStatusCode() + " creating user\n\n");

                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    JSONObject jsonResponse = new JSONObject(new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Authenticate response: " + jsonResponse.toString(2));
                    }

                    Object attributeValObj = jsonResponse.opt("access_token");
                    if (attributeValObj instanceof String) {
                        if (isDebugEnabled) {
                            log.debug("Access token is: " + (String) attributeValObj);
                        }
                        return (String) attributeValObj;
                    } else {
                        log.error("Authentication response type: " + attributeValObj.toString() + " is invalid");
                    }
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: "+ response.getStatusLine().getReasonPhrase());
                }
            } catch (JSONException | IOException e) {
                throw new IdentityProvisioningException("Error in decoding response to JSON", e);
            } finally {
                post.releaseConnection();
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }

        return "";
    }
    
    private String authenticateArionStargate() throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String apikey = configHolder.getValue(ArionConnectorConstants.PropertyConfig.CLIENT_SECRET);
        if (isDebugEnabled) {
        	log.debug("Hamizan checking api key in authenticateArionStargate(): " + apikey);
        }

        return apikey;
    }
    
    private String getApiUser() throws IdentityProvisioningException {

        boolean isDebugEnabled = log.isDebugEnabled();

        String apiuser = configHolder.getValue(ArionConnectorConstants.PropertyConfig.USERNAME);
        if (isDebugEnabled) {
        	log.debug("Hamizan checking api username in getApiUser(): " + apiuser);
        }

        return apiuser;
    }

    /**
     * builds salesforce user end point using configurations
     *
     * @return
     */
    private String getUserObjectEndpoint() {

        boolean isDebugEnabled = log.isDebugEnabled();

        /*
        String url = configHolder.getValue(ArionConnectorConstants.PropertyConfig.DOMAIN_NAME)
                   + ArionConnectorConstants.CONTEXT_SERVICES_DATA 
                   + configHolder.getValue(ArionConnectorConstants.PropertyConfig.API_VERSION)
                   + ArionConnectorConstants.CONTEXT_SOOBJECTS_USER;
        */
        String url = configHolder.getValue(ArionConnectorConstants.PropertyConfig.DOMAIN_NAME)
//                + ArionConnectorConstants.PORT 
                + ArionConnectorConstants.CONTEXT_SERVICES_DATA;
        if (isDebugEnabled) {
            log.debug("Built user endpoint url : " + url);
        }

        return url;
    }

    /**
     * Builds Salesforce query point using configurations
     *
     * @return
     */
    private String getDataQueryEndpoint() {
        if (log.isTraceEnabled()) {
            log.trace("Starting getDataQueryEndpoint() of " + ArionProvisioningConnector.class);
        }
        boolean isDebugEnabled = log.isDebugEnabled();

        String url = configHolder.getValue(ArionConnectorConstants.PropertyConfig.DOMAIN_NAME)
                + ArionConnectorConstants.CONTEXT_SERVICES_DATA + configHolder.getValue(ArionConnectorConstants.PropertyConfig.API_VERSION)
                + ArionConnectorConstants.CONTEXT_QUERY;
        if (isDebugEnabled) {
            log.debug("Built query endpoint url: " + url);
        }

        return url;
    }

    /**
     * @return
     * @throws IdentityProvisioningException
     */
    public String listUsers(String query) throws IdentityProvisioningException {

        if (log.isTraceEnabled()) {
            log.trace("Starting listUsers() of " + ArionProvisioningConnector.class);
        }
        boolean isDebugEnabled = log.isDebugEnabled();

        if (StringUtils.isBlank(query)) {
            query = ArionConnectorDBQueries.SALESFORCE_LIST_USER_SIMPLE_QUERY;
        }

        StringBuilder sb = new StringBuilder();
        try (CloseableHttpClient httpclient = HttpClientBuilder.create().useSystemProperties().build()) {
            HttpGet get = new HttpGet(this.getDataQueryEndpoint());
            setAuthorizationHeader(get);

            try {
                // set the SOQL as a query param
                URI uri = new URIBuilder(get.getURI()).addParameter("q", query).build();
                get.setURI(uri);
            } catch (URISyntaxException e) {
                throw new IdentityProvisioningException("Error in Building the URI", e);
            }

            try (CloseableHttpResponse response = httpclient.execute(get)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                    JSONObject jsonResponse = new JSONObject(
                            new JSONTokener(new InputStreamReader(response.getEntity().getContent())));
                    if (isDebugEnabled) {
                        log.debug("Query response: " + jsonResponse.toString(2));
                    }

                    // Build the returning string
                    sb.append(jsonResponse.getString("totalSize") + " record(s) returned\n\n");
                    JSONArray results = jsonResponse.getJSONArray("records");
                    for (int i = 0; i < results.length(); i++) {
                        sb.append(results.getJSONObject(i).getString("Id") + ", " + 
                        		results.getJSONObject(i).getString("Alias") + ", " + 
                        		results.getJSONObject(i).getString("Email") + ", " +
                                results.getJSONObject(i).getString("LastName") + ", " +
                                results.getJSONObject(i).getString("Name") + ", " + 
                                results.getJSONObject(i).getString("ProfileId") + ", " + 
                                results.getJSONObject(i).getString("Username") +
                                "\n");
                    }
                    sb.append("\n");
                } else {
                    log.error("Received response status code: " + response.getStatusLine().getStatusCode() + " text: "+ response.getStatusLine().getReasonPhrase());
                }
            } catch (JSONException | IOException e) {
                log.error("Error in invoking provisioning operation for the user listing");
                throw new IdentityProvisioningException(e);
            } finally {
                get.releaseConnection();
            }

            if (isDebugEnabled) {
                log.debug("Returning string: " + sb.toString());
            }

            if (log.isTraceEnabled()) {
                log.trace("Ending listUsers() of " + ArionProvisioningConnector.class);
            }
        } catch (IOException e) {
            log.error("Error while closing HttpClient.");
        }
        return sb.toString();
    }

    /**
     * Alter username while changing user to active state to inactive state. This is necessary when adding previously
     * deleted users.
     *
     * @param provisioningEntity
     * @return
     * @throws IdentityProvisioningException
     */
    protected String alterUsername(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        if (StringUtils.isBlank(provisioningEntity.getEntityName())) {
            throw new IdentityProvisioningException("Could Not Find Entity Name from Provisioning Entity");
        }
        String alteredUsername = ArionConnectorConstants.ARION_OLD_USERNAME_PREFIX + UUIDGenerator.generateUUID()+ provisioningEntity.getEntityName();

        if (log.isDebugEnabled()) {
            log.debug("Alter username: " + provisioningEntity.getEntityName() + " to: " + alteredUsername+ "while deleting user");
        }
        return alteredUsername;
    }
}
