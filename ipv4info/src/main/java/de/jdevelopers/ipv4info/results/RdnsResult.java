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

package de.jdevelopers.ipv4info.results;

import java.io.Serializable;

import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Result-Object for RDNS-Calls.
 *
 * @author Carsten Jäger
 *
 */
public class RdnsResult implements Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -264144650056393027L;

    /**
     * IP-Address.
     */
    private String ip;

    /**
     * RDNS-Entry.
     */
    private String rdns;

    /**
     * RDNS-WHOIS-Entry.
     */
    private String rdnsWhois;

    /**
     * IP-WHOIS-Entry.
     */
    private String rdnsIpWhois;

    /**
     * Constructor.
     *
     * @param ip IP-Address.
     */
    public RdnsResult(final String ip) {
        super();
        this.ip = ip;
    }

    /**
     * Returns the value of the IP-Address.
     *
     * @return Returns the value of the IP-Address.
     */
    public final String getIp() {
        return ip;
    }

    /**
     * Sets the value of rdns.
     *
     * @param rdns The value of rdns.
     */
    public final void setRdns(final String rdns) {
        this.rdns = rdns;
    }

    /**
     * Returns the value of te RDNS-Entry.
     *
     * @return Returns the value of the RDNS-Entry.
     */
    public final String getRdns() {
        return rdns;
    }

    /**
     * @return Returns the value of rdnsWhois.
     */
    public final String getRdnsWhois() {
        return rdnsWhois;
    }

    /**
     * @param rdnsWhois Sets the value of rdnsWhois.
     */
    public final void setRdnsWhois(final String rdnsWhois) {
        this.rdnsWhois = rdnsWhois;
    }

    /**
     * @return Returns the value of rdnsIpWhois.
     */
    public final String getRdnsIpWhois() {
        return rdnsIpWhois;
    }

    /**
     * @param ipWhois Sets the value of rdnsIpWhois.
     */
    public final void setRdnsIpWhois(final String ipWhois) {
        this.rdnsIpWhois = ipWhois;
    }

    @Override
    public final String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("IP: ").append(Ipv4Utils.expandStringToLength(getIp(), Ipv4Utils.CONST_5 + Ipv4Utils.CONST_10, false))
          .append(" -> RDNS: ").append(getRdns()).append("\n");
        return sb.toString();
    }

}
