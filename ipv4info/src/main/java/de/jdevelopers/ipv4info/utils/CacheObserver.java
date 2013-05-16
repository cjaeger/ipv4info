/*
* Copyright 2013, Carsten Jäger
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

package de.jdevelopers.ipv4info.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

import de.jdevelopers.ipv4info.objects.IpInfo;

/**
 * TimerTask that takes care of the cache sizes to avoid to consume too much memory.
 *
 * All entries from the Ipv4Utils.RESULT_POOL map will be removed if they are not accessed for Ipv4Utils.INTERNAL_CACHE_TTL.
 *
 * @author Carsten Jäger
 *
 */
class CacheObserver extends TimerTask {

    /**
     * Maximum lifetime of unresolved objects in Ipv4Utils.RESULT_POOL (1 hour).
     */
    private static final long MAX_UNRESOLVED_TTL = TimeUnit.HOURS.toMillis(1);

    /**
     * List that holds the strings (queries/servers) to remove from the caches.
     */
    private static final List<String> REMOVE_LIST = new ArrayList<String>();

    @Override
    public final void run() {
//        System.err.println("### Running CacheObserver!");
        final long actualTime = System.currentTimeMillis();
        try {
            REMOVE_LIST.clear();
            if (!Ipv4Utils.RESULT_POOL.isEmpty()) {
                synchronized (Ipv4Utils.RESULT_POOL) {
                    for (String query : Ipv4Utils.RESULT_POOL.keySet()) {
                        final IpInfo ipInfo = Ipv4Utils.RESULT_POOL.get(query);
                        if (!ipInfo.isAnyResolveActionPerformed()) {
                            if (ipInfo.getLastAccessed() == 0) {
                                ipInfo.setLastAccessed(System.currentTimeMillis());
                            } else {
                                // If there was no request to resolve anything for MAX_UNRESOLVED_TTL we drop this entry anyway...
                                if ((actualTime - ipInfo.getLastAccessed()) >= MAX_UNRESOLVED_TTL) {
                                    REMOVE_LIST.add(query);
                                }
                            }
                            continue;
                        }
                        if ((actualTime - ipInfo.getLastAccessed()) > Ipv4Utils.getInternalCacheTTL(TimeUnit.MILLISECONDS)) {
                            REMOVE_LIST.add(query);
                        }
                    }
                    for (String query : REMOVE_LIST) {
                        System.err.println("### Removing from RESULT_POOL because lifetime expired: " + query + " -> "
                                + Ipv4Utils.RESULT_POOL.get(query).getLastAccessed());
                        Ipv4Utils.RESULT_POOL.remove(query);
                    }
                }
            }
        } finally {
            REMOVE_LIST.clear();
        }
    }

}
