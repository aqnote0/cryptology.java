/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt;

import java.security.Provider;
import java.security.Security;

import org.apache.commons.lang.StringUtils;

/**
 * ProviderUtils.java desc：TODO
 * 
 * @author madding.lip Jan 9, 2017 10:22:24 AM
 */
public class ProviderUtil {

    public static void resetToProvider(Provider provider) {
        removeAllProvider();
        Security.insertProviderAt(provider, 1);
    }

    @SuppressWarnings("unchecked")
    public static void addProvider(String className) throws Exception {
        if (StringUtils.isBlank(className)) return;
        Class<?> clazz = Class.forName(className);
        if (clazz == null || !clazz.isAssignableFrom(Provider.class)) return;
        addProvider((Class<Provider>) clazz);
    }

    public static void addProvider(Class<Provider> clazz) throws Exception {
        Provider provider = clazz.getConstructor().newInstance();
        addProvider(provider);
    }

    public static void addProvider(Provider provider) throws Exception {
        if (provider == null || Security.getProvider(provider.getName()) != null) return;
        Security.insertProviderAt(provider, 1);
    }

    @SuppressWarnings("unchecked")
    public static void removeProvider(String className) throws Exception {
        if (StringUtils.isBlank(className)) return;
        Class<?> clazz = Class.forName(className);
        if (clazz == null || !clazz.isAssignableFrom(Provider.class)) return;
        removeProvider((Class<Provider>) clazz);
    }

    public static void removeProvider(Class<Provider> clazz) throws Exception {
        Provider provider = clazz.getConstructor().newInstance();
        removeProvider(provider);
    }

    public static void removeProvider(Provider provider) throws Exception {
        if (provider == null || Security.getProvider(provider.getName()) == null) return;
        Security.removeProvider(provider.getName());
    }

    public static void removeAllProvider() {
        for (Provider p : Security.getProviders()) {
            Security.removeProvider(p.getName());
        }
    }
}
