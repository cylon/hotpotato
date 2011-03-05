/*
 * Copyright 2010 Bruno de Carvalho
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

package com.biasedbit.hotpotato.client.host.factory;

import com.biasedbit.hotpotato.client.host.EagerDrainHostContext;
import com.biasedbit.hotpotato.client.host.HostContext;

/**
 * @author <a href="http://bruno.biasedbit.com/">Bruno de Carvalho</a>
 */
public class EagerDrainHostContextFactory implements HostContextFactory {

    // HostContextFactory ---------------------------------------------------------------------------------------------


    public HostContext createHostContext(final String host, final int port, final int maxConnections) {
        return new EagerDrainHostContext(host, port, maxConnections);
    }
}