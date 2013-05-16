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
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.objects.IpInfoOptions;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Result-Object for MX-Calls.
 *
 * @author Carsten Jäger
 *
 */
public class MxResult implements Comparable<MxResult>, Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -307231255129483125L;

    /**
     * List of MX-Domains known as a pitfall.
     */
    private static List<String> pitfalls;

    /**
     * Resolved MX-Domain.
     */
    private String domain;

    /**
     * MX-Priority.
     */
    private int priority = 1;

    /**
     * Time to live (TTL).
     */
    private long ttl;

    /**
     * The port for SMTP connections.
     */
    private int smtpPort = Ipv4Utils.SMTP_PORT;

    /**
     * Timestamp of when the MX request was started.
     */
    private long requestStart;

    /**
     * Timestamp of when the MX request was finished.
     */
    private long  requestEnd;

    /**
     * Will be set to true, if the domain matches to the Ipv4Utils.BLACKHOLE_PATTERN.
     */
    private boolean blackholeSuspect;

    /**
     * Is this entry a doublet of another entry?.
     */
    private boolean isDoublet;

    /**
     * Has this entry any doublets?
     */
    private boolean hasDoublet;

    /**
     * Flag, that shows if the MX domain is disabled.
     */
    private boolean disabled;

    /**
     * Is this domain reachable?
     */
    private boolean domainReachable;

    /**
     * IpInfoOptions object.
     */
    private IpInfoOptions ipInfoOptions;

    /**
     * Resolved IP's for the MX-Domain.
     */
    private Map<String, Boolean> mxIps;

    static {
        // List of known MX pitfall addresses (More addresses? Add them to DefaultConfig.xml).
        pitfalls = Ipv4Utils.getPitfalls();
        if (pitfalls == null) {
        	pitfalls = new ArrayList<String>();
        }
    }

    /**
     * Constructor.
     *
     * @param domain Domain.
     * @param priority Priority.
     * @param ttl TTL (Time to live).
     * @param ipInfoOptions IpInfoOptions object.
     */
    public MxResult(final String domain, final int priority, final long ttl, final IpInfoOptions ipInfoOptions) {
        super();
        this.domain = domain;
        this.priority = priority;
        this.ttl = ttl;
        this.ipInfoOptions = ipInfoOptions;
        if (isPitfall()) {
            setDisabled(true);
            setDomainReachable(false);
        }
    }

    /**
     * Returns if the MX-Domain is known as a pitfall.
     *
     * @return {@code TRUE} if it's known as a pitfall, otherwise {@code TRUE}.
     */
    public final boolean isPitfall() {
        return pitfalls.contains(domain.toLowerCase());
    }

    /**
     * @return Returns the value of domain.
     */
    public final String getDomain() {
        return domain;
    }

    /**
     * @return Returns the value of priority.
     */
    public final int getPriority() {
        return priority;
    }

    /**
     * @return Returns the value of ttl.
     */
    public final long getTTL() {
        return ttl;
    }

    /**
     * Returns the value of smtpPort.
     *
     * @return The value of smtpPort.
     */
    public final int getSmtpPort() {
        return smtpPort;
    }

    /**
     * Sets the value of smtpPort.
     *
     * @param smtpPort The value of smtpPort.
     */
    public final void setSmtpPort(final int smtpPort) {
        this.smtpPort = smtpPort;
    }

    /**
     * @return Returns the value of requestStart.
     */
    public final long getRequestStart() {
        return requestStart;
    }

    /**
     * @param requestStart Sets the value of requestStart.
     */
    public final void setRequestStart(final long requestStart) {
        this.requestStart = requestStart;
    }

    /**
     * @return Returns the value of requestEnd.
     */
    public final long getRequestEnd() {
        return requestEnd;
    }

    /**
     * @param requestEnd Sets the value of requestEnd.
     */
    public final void setRequestEnd(final long requestEnd) {
        this.requestEnd = requestEnd;
    }

    /**
     * @return Returns the value of blackholeSuspect.
     */
    public final boolean isBlackholeSuspect() {
        return blackholeSuspect;
    }

    /**
     * @param blackholeSuspect Sets the value of blackholeSuspect.
     */
    public final void setBlackholeSuspect(final boolean blackholeSuspect) {
        this.blackholeSuspect = blackholeSuspect;
    }

    /**
     * Returns the value of isDoublet.
     *
     * @return The value of isDoublet.
     */
    public final boolean isDoublet() {
        return isDoublet;
    }

    /**
     * Sets the value of isDoublet.
     *
     * @param isDoublet The value of isDoublet.
     */
    public final void setDoublet(final boolean isDoublet) {
        this.isDoublet = isDoublet;
    }

    /**
     * Returns the value of hasDoublet.
     *
     * @return The value of hasDoublet.
     */
    public final boolean isHasDoublet() {
        return hasDoublet;
    }

    /**
     * Sets the value of hasDoublet.
     *
     * @param hasDoublet The value of hasDoublet.
     */
    public final void setHasDoublet(final boolean hasDoublet) {
        this.hasDoublet = hasDoublet;
    }

    /**
     * @return Returns the value of disabled.
     */
    public final boolean isDisabled() {
        return disabled;
    }

    /**
     * @param disabled Sets the value of disabled.
     */
    public final void setDisabled(final boolean disabled) {
        this.disabled = disabled;
    }

    /**
     * Returns the value of domainReachable.
     *
     * @return The value of domainReachable.
     */
    public final boolean isDomainReachable() {
        return domainReachable;
    }

    /**
     * Sets the value of domainReachable.
     *
     * @param domainReachable The value of domainReachable.
     */
    public final void setDomainReachable(final boolean domainReachable) {
        this.domainReachable = domainReachable;
        if (!this.domainReachable) {
            setDisabled(true);
        }
    }

    /**
     * @return Returns the value of mxIps.
     */
    public final Map<String, Boolean> getMxIps() {
        return mxIps;
    }

    /**
     * Adds a Collections of Ip's to the mxIps collection.
     *
     * @param ips Collection of Ip's.
     */
    public final void addToMxIps(final Map<String, Boolean> ips) {
        if (ips == null || ips.isEmpty()) {
            return;
        }
        if (mxIps == null) {
            mxIps = new TreeMap<String, Boolean>();
        }
        for (String ip : ips.keySet()) {
            mxIps.put(ip, ips.get(ip));
        }
        ips.clear();
    }

    /**
     * Convenience function to check if there were found MX-Ip's.
     *
     * @return {@code TRUE}, if there were found MX-Ip's, otherwise {@code FALSE}.
     */
    public final boolean hasMxIps() {
        return mxIps != null && !mxIps.isEmpty();
    }

    /**
     * Clears the Collection of Mx Ip's.
     */
    public final void clear() {
        if (mxIps != null) {
            mxIps.clear();
        }
    }

    @Override
    public final int hashCode() {
        return (domain == null) ? 0 : domain.hashCode();
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
        MxResult other = (MxResult) obj;
        if (domain == null) {
            if (other.domain != null) {
                return false;
            }
        } else if (!domain.equals(other.domain)) {
            return false;
        }
        return true;
    }

    public final int compareTo(final MxResult mxResult) {
        return domain.compareTo(mxResult.getDomain());
    }

    @Override
    public final String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Domain/IP          : ").append(getDomain()).append("\n")
          .append("Requested at       : ").append(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.LONG).format(requestStart)).append("\n")
          .append("Resolve duration   : ").append((requestEnd - requestStart)).append(" msec\n")
          .append("Priority           : ").append(getPriority()).append("\n")
          .append("TTL                : ").append(getTTL()).append(" sec\n");
        if (ipInfoOptions.getMxOptionList().contains(EMxOption.MARK_DOUBLETTES)) {
            sb.append("Is Doublet         : ").append(isDoublet()).append("\n");
            sb.append("Has doublet        : ").append(isHasDoublet()).append("\n");
        }
        if (!ipInfoOptions.getMxOptionList().contains(EMxOption.SKIP_BLACKHOLES)) {
            sb.append("Possible blackhole : ").append(isBlackholeSuspect()).append("\n");
        }
        if (!ipInfoOptions.getMxOptionList().contains(EMxOption.SKIP_PITFALLS)) {
            sb.append("Known pitfall      : ").append(isPitfall()).append("\n");
        }
        sb.append("Reachable          : ").append(ipInfoOptions.getMxOptionList().contains(EMxOption.VERIFY_DOMAIN) ? isDomainReachable()
                  : !isPitfall() ? "not verified" : false).append("\n");
        if (!ipInfoOptions.getMxOptionList().contains(EMxOption.SKIP_DISABLED)) {
            sb.append("Disabled           : ").append(isDisabled()).append("\n");
        }
        if (getMxIps() != null || isDisabled() || isPitfall()) {
            if ((isDisabled() || isPitfall()) && (ipInfoOptions.getMxOptionList().contains(EMxOption.RESOLVE_IPS)
                    || ipInfoOptions.getMxOptionList().contains(EMxOption.VERIFY_IPS))) {
                sb.append("Resolved MX-IP's   : 0\n");
            } else {
                if (getMxIps() != null) {
                    sb.append("Resolved MX-IP's   : ").append(getMxIps() != null ? getMxIps().size() : 0).append("\n");
                    for (final String ip : getMxIps().keySet()) {
                        sb.append("MX-IP              : ").append(Ipv4Utils.expandStringToLength(ip, Ipv4Utils.CONST_5 + Ipv4Utils.CONST_10, true))
                        .append(" -> Reachable: ").append(ipInfoOptions.getMxOptionList().contains(EMxOption.VERIFY_IPS)
                                ? getMxIps().get(ip) : "not verified").append("\n");
                    }
                }
            }
        }
        return sb.toString();
    }

}
