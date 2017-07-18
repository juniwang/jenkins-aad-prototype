/*
 Copyright 2017 Microsoft Open Technologies, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package org.jenkinsci.plugins.azureaad;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import jenkins.security.SecurityListener;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetailsService;
import org.kohsuke.stapler.*;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class AzureADRealm extends SecurityRealm implements UserDetailsService {
    private static final String REFERER_ATTRIBUTE = AzureADRealm.class.getName() + ".referer";

    private String clientId = "testing";
    private String clientSecret="testing secret";

    private String authority = "https://login.microsoftonline.com/common/";
//    private String authority = "https://login.chinacloudapi.cn/common/";

    private AzureADRealm() {
        super();
    }

    @DataBoundConstructor
    public AzureADRealm(String clientId, String clientSecret) {
        super();
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = Util.fixEmptyAndTrim(clientId);
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public static final class ConverterImpl implements Converter {
        public boolean canConvert(Class type) {
            return type == AzureADRealm.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
            AzureADRealm realm = (AzureADRealm) source;

            writer.startNode("clientID");
            writer.setValue(realm.getClientId());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();

            writer.startNode("authority");
            writer.setValue(realm.getClientSecret());
            writer.endNode();
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
            AzureADRealm realm = new AzureADRealm();

            String node;
            String value;

            while (reader.hasMoreChildren()) {
                reader.moveDown();
                node = reader.getNodeName();
                value = reader.getValue();
                setValue(realm, node, value);
                reader.moveUp();
            }
            return realm;
        }

        private void setValue(AzureADRealm realm, String node, String value) {
            if (node.toLowerCase().equals("clientid")) {
                realm.setClientId(value);
            } else if (node.toLowerCase().equals("clientsecret")) {
                realm.setClientSecret(value);
            } else if (node.toLowerCase().equals("authority")) {
                realm.setAuthority(value);
            } else {
                throw new ConversionException("Invalid node value = " + node);
            }
        }
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    private String buildFullAuthorizeUri() {
        StringBuilder stringBuilder = new StringBuilder();

        stringBuilder.append(authority)
                .append("oauth2/authorize")
                .append("?client_id=").append(clientId)
                .append("&response_type=code");

        return stringBuilder.toString();
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer)
            throws IOException {
        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        // Building OAuth request URI happens here...
        String requestURI = buildFullAuthorizeUri();
        return new HttpRedirect(requestURI);
    }

    /**
     * This is where the user comes back to at the end of the OAuth redirect
     * ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request)
            throws IOException {
        final String code = request.getParameter("code");
        if (code == null || code.trim().length() == 0) {
            return HttpResponses.redirectToContextRoot();
        }

        AuthenticationResult result = getAccessToken(code, request.getRequestURI());
        if (result != null) {
            AADToken token = new AADToken(result);
            SecurityContextHolder.getContext().setAuthentication(token);
            SecurityListener.fireAuthenticated(token.getUser());
        }

        return HttpResponses.redirectToContextRoot();
    }

    private AuthenticationResult getAccessToken(@Nonnull String code, String currentUri) throws IOException {
        ClientCredential credential = new ClientCredential(clientId, clientSecret);
        AuthenticationResult result = null;
        ExecutorService service = Executors.newFixedThreadPool(1);
        try {
            AuthenticationContext context = new AuthenticationContext(authority, true, service);
            Future<AuthenticationResult> future = context.acquireTokenByAuthorizationCode(code, new URI(currentUri), credential, null);
            result = future.get();
        } catch (Exception e) {

        } finally {
            service.shutdown();
        }

        return result;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof AADToken)
                    return authentication;
                throw new BadCredentialsException("Unexpected type:" + authentication);
            }
        });
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "AAD OAuth Code Authentication";
        }
    }
}
