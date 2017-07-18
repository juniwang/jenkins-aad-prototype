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

import com.microsoft.aad.adal4j.AuthenticationResult;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;

import javax.annotation.Nonnull;

public class AADToken extends AbstractAuthenticationToken {
    private AADUser user;
    private AuthenticationResult result;

    public AADToken(@Nonnull AuthenticationResult result) {
        user = new AADUser(result.getUserInfo());
        setAuthenticated(result != null);
        this.result = result;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return user != null ? user.getAuthorities() : new GrantedAuthority[0];
    }

    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }

    @Override
    public String getName() {
        return (user != null ? user.getUsername() : null);
    }

    public AADUser getUser() {
        return user;
    }

    public AuthenticationResult getResult() {
        return result;
    }
}