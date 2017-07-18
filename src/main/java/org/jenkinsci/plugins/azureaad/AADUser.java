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

import com.microsoft.aad.adal4j.UserInfo;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

public class AADUser implements UserDetails {
    private UserInfo userInfo;
    private List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

    public AADUser(@Nonnull UserInfo userInfo) {
        super();
        this.userInfo = userInfo;
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        //return new GrantedAuthority[0];
        return authorities.toArray(new GrantedAuthority[authorities.size()]);
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return userInfo.getUniqueId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
