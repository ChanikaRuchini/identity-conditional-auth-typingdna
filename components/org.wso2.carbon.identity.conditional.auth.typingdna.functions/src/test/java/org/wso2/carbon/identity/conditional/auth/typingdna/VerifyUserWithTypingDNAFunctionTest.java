/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.typingdna;

import org.apache.catalina.util.ParameterMap;
import org.mockito.Mockito;
import org.opensaml.xmlsec.signature.P;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsParameters;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.CacheBackedLongWaitStatusDAO;
import org.wso2.carbon.identity.application.authentication.framework.dao.impl.LongWaitStatusDAOImpl;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.store.LongWaitStatusStoreService;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.common.testng.InjectMicroservicePort;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithMicroService;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.conditional.auth.functions.common.internal.FunctionsDataHolder;
import org.wso2.carbon.identity.conditional.auth.functions.test.utils.sequence.JsSequenceHandlerAbstractTest;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithMicroService
@WithH2Database(files = {"dbscripts/h2.sql"})
@WithRealmService(injectToSingletons = {IdentityTenantUtil.class, FrameworkServiceDataHolder.class})
@Path("/")
public class VerifyUserWithTypingDNAFunctionTest extends JsSequenceHandlerAbstractTest {

    @WithRealmService
    private RealmService realmService;

    @InjectMicroservicePort
    private int microServicePort;

    @BeforeMethod
    protected void setUp() throws Exception {

        super.setUp();

        sequenceHandlerRunner.registerJsFunction("verifyUserWithTypingDNA", new VerifyUserWithTypingDNAFunctionImpl());
        UserRealm userRealm = realmService.getTenantUserRealm(-1234);
        userRealm.getUserStoreManager().addRole("admin", new String[]{"admin", "test_user"}, null);
    }

    @Test
    public void testRiskScore() throws Exception {


        IdentityGovernanceService identityGovernanceService = Mockito.mock(IdentityGovernanceService.class);
        FunctionsDataHolder functionsDataHolder = Mockito.mock(FunctionsDataHolder.class);
        Mockito.when(functionsDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);

        Property property = new Property();
        property.setValue("true");
        Mockito.when(identityGovernanceService.getConfiguration(new String[]{TypingDNAConfigImpl.ENABLE},
                "carbon.super")).thenReturn(new Property[]{property});

    /*    Property property2 = new Property();
        property2.setValue("https://localhost:" + microServicePort);
        Mockito.when(identityGovernanceService.getConfiguration(new String[]{TypingDNAConfigImpl.RECEIVER},
                "carbon.super")).thenReturn(new Property[]{property2});*/

        IdentityCoreServiceDataHolder.getInstance().setRealmService(realmService);
        Field functionsDataHolderInstance = FunctionsDataHolder.class.getDeclaredField("instance");
        functionsDataHolderInstance.setAccessible(true);
        functionsDataHolderInstance.set(null, functionsDataHolder);

        Field frameworkServiceDataHolderInstance = FrameworkServiceDataHolder.class.getDeclaredField("instance");
        frameworkServiceDataHolderInstance.setAccessible(true);
        FrameworkServiceDataHolder availableInstance = (FrameworkServiceDataHolder) frameworkServiceDataHolderInstance
                .get(null);

        LongWaitStatusDAOImpl daoImpl = new LongWaitStatusDAOImpl();
        CacheBackedLongWaitStatusDAO cacheBackedDao = new CacheBackedLongWaitStatusDAO(daoImpl);
        int connectionTimeout = 5000;
        LongWaitStatusStoreService longWaitStatusStoreService =
                new LongWaitStatusStoreService(cacheBackedDao, connectionTimeout);
        availableInstance.setLongWaitStatusStoreService(longWaitStatusStoreService);

        ServiceProvider sp1 = sequenceHandlerRunner.loadServiceProviderFromResource("risk-test-sp.xml",
                this);
        AuthenticationContext context = sequenceHandlerRunner.createAuthenticationContext(sp1);
        SequenceConfig sequenceConfig = sequenceHandlerRunner
                .getSequenceConfig(context, sp1);
        context.setSequenceConfig(sequenceConfig);
        JsServletRequest jsServletRequest = mock(JsServletRequest.class);

        TransientObjectWrapper transientObjectWrapper = mock(TransientObjectWrapper.class);
        context.setProperty("HttpServletRequest",  transientObjectWrapper);
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(transientObjectWrapper.getWrapped()).thenReturn(httpServletRequest);

        ParameterMap parameterMap = new ParameterMap();
        parameterMap.put("typingPattern", new String[]{"dummyPattern"});
        when(httpServletRequest.getParameterMap()).thenReturn(parameterMap);

        when(jsServletRequest.getMember(anyString())).thenReturn(mock(JsParameters.class));
        context.initializeAnalyticsData();


        HttpServletRequest req = sequenceHandlerRunner.createHttpServletRequest();
        HttpServletResponse resp = sequenceHandlerRunner.createHttpServletResponse();

      //  VerifyUserWithTypingDNAFunctionImpl mock = spy(new VerifyUserWithTypingDNAFunctionImpl());
       //PowerMockito.when(mock, "buildURL", "anyString()", "anyString", "anyString()").thenReturn("https:localhost:8080");

        //PowerMockito.whenNew(VerifyUserWithTypingDNAFunctionImpl.class).withNoArguments().thenReturn(mock);

        sequenceHandlerRunner.handle(req, resp, context, "carbon.super");

    //    assertNotNull(context.getSelectedAcr());
        assertEquals(context.getSelectedAcr(), "1", "Expected acr value not found");
    }

    @POST
    @Path("/{api}/{userID}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/json")
    public Map<String, String> typingDNAReceiver(@PathParam("api") String api,
                                                 @PathParam("userID") String userID,
                                                 @FormParam("data") String data) {

        System.out.println("api....................."+ api);
        Map<String, String> response = new HashMap<>();
        response.put("result", "1");
        response.put("message_code", "1");
        response.put("score", "1");
        response.put("confidence", "98");
        response.put("compared_samples", "1");
        return response;
    }
}
