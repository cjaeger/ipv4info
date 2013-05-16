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

package de.jdevelopers.ipv4info.objects;

import java.io.Serializable;
import java.util.Map;
import java.util.TreeMap;

import de.jdevelopers.ipv4info.results.RdnsResult;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Object that holds the RDNS summary.
 *
 * @author Carsten Jäger
 *
 */
public class RdnsInfo implements Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -4322765755871935500L;

    /**
     * Map of RdnsResult-Objects.
     */
    private Map<String, RdnsResult> rdnsResults;

    /**
     * Reference to the resulting IpInfo-Object.
     */
    private IpInfo ipInfo;

    /**
     * Query domain/IP.
     */
    private String query;

    /**
     * Constructor.
     *
     * @param query Domain/IP.
     * @param ipInfo Reference to the resulting IpInfo-Object.
     */
    public RdnsInfo(final String query, final IpInfo ipInfo) {
        super();
        this.query = query;
        this.ipInfo = ipInfo;
        rdnsResults = new TreeMap<String, RdnsResult>();
    }

    /**
     * Returns the value of rdnsResults.
     *
     * @return The value of rdnsResults.
     */
    public final Map<String, RdnsResult> getRdnsResult() {
        return rdnsResults;
    }

    /**
     * Adds a RdnsResult-Object to the internal result map.
     *
     * @param rdnsResult RdnsResult-Object.
     */
    public final void addToRdnsResultMap(final RdnsResult rdnsResult) {
        rdnsResults.put(rdnsResult.getIp(), rdnsResult);
    }

    /**
     * Returns the value of query.
     *
     * @return The value of query.
     */
    public final String getQuery() {
        return query;
    }

    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((query == null) ? 0 : query.hashCode());
        result = prime * result + ((rdnsResults == null) ? 0 : rdnsResults.hashCode());
        return result;
    }

    @Override
    public final boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        RdnsInfo other = (RdnsInfo) obj;
        if (query == null) {
            if (other.query != null) {
                return false;
            }
        } else if (!query.equals(other.query)) {
            return false;
        }
        if (rdnsResults == null) {
            if (other.rdnsResults != null) {
                return false;
            }
        } else if (!rdnsResults.equals(other.rdnsResults)) {
            return false;
        }
        return true;
    }

    @Override
    public final String toString() {
        final StringBuilder sb = new StringBuilder(Ipv4Utils.DIVIDER);
        if (!getRdnsResult().isEmpty()) {
            sb.append("RDNS info for \"").append(query).append("\":\n");
            sb.append(Ipv4Utils.DIVIDER);
            for (RdnsResult rdnsResult : getRdnsResult().values()) {
                sb.append(rdnsResult);
            }
        } else {
            sb.append("RDNS info for \"").append(query).append("\" not");
            if (!ipInfo.isResolvable()) {
                if (ipInfo.isDomain()) {
                    sb.append(" possible (NXDOMAIN)");
                } else if (ipInfo.isIp()) {
                    sb.append(" possible (INVALIDIP)");
                }
            } else {
                sb.append(" found (NORDNS)");
            }
            sb.append(".\n");
        }
        return sb.toString();
    }

}
