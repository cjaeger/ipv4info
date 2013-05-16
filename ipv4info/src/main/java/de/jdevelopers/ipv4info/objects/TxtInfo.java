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
import java.util.ArrayList;
import java.util.List;

import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Result-Object for TXT-Calls.
 *
 * @author Carsten Jäger
 *
 */
public class TxtInfo implements Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -1670396803533074353L;

    /**
     * Reference to the resulting IpInfo-Object.
     */
    private IpInfo ipInfo;

    /**
     * Query domain/IP.
     */

    private String query;

    /**
     * List of TXT entries.
     */
    private List<String> txtEntryList;

    /**
     * Constructor.
     *
     * @param query Query domain/IP.
     * @param ipInfo Reference to the resulting IpInfo-Object.
     */
    public TxtInfo(final String query, final IpInfo ipInfo) {
        super();
        this.query = query;
        this.ipInfo = ipInfo;
        txtEntryList = new ArrayList<String>();
    }

    /**
     * Returns the value of txtResultLIst.
     *
     * @return The value of txtResultLIst.
     */
    public final List<String> getTxtResultList() {
        return txtEntryList;
    }

    /**
     * Adds an entry to txtEntryList.
     *
     * @param txtEntry TXT entry.
     */
    public final void addToTxtEntryList(final String txtEntry) {
        txtEntryList.add(txtEntry);
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
    public final String toString() {
        final StringBuilder sb = new StringBuilder(Ipv4Utils.DIVIDER);
        if (!getTxtResultList().isEmpty()) {
            sb.append("TXT info for \"").append(query).append("\":\n");
            sb.append(Ipv4Utils.DIVIDER);
            for (int i = 0; i < getTxtResultList().size(); ++i) {
                sb.append(i + 1).append(": ");
                if (getTxtResultList().get(i).length() > (Ipv4Utils.CONST_100 - (Ipv4Utils.CONST_5 + Ipv4Utils.CONST_3))) {
                    sb.append(getTxtResultList().get(i).substring(0, (Ipv4Utils.CONST_100 - (Ipv4Utils.CONST_5 + Ipv4Utils.CONST_3)))).append(" [...]");
                } else {
                    sb.append(getTxtResultList().get(i));
                }
                sb.append("\n");
            }
        } else {
            sb.append("TXT info for \"").append(query).append("\" not");
            if (!ipInfo.isResolvable()) {
                if (ipInfo.isDomain()) {
                    sb.append(" possible (NXDOMAIN)");
                } else if (ipInfo.isIp()) {
                    sb.append(" possible (INVALIDIP)");
                }
            } else {
                sb.append(" found (NOTXT)");
            }
            sb.append(".\n");
        }
        return sb.toString();
    }

}
