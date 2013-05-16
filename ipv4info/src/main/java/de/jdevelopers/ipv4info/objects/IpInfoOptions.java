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
import java.util.List;

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.enums.EMxOption;

/**
 * Object that holds the options for an IpInfo query.
 *
 * @author Carsten Jäger
 *
 */

public class IpInfoOptions implements Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -4653304432405708630L;

    /**
     * The IP/Subnet/Hostname to query.
     */
    private String query;

    /**
     * Shall RDNS entries be resolved?
     */
    private boolean resolveRdns;

    /**
     * Shall TXT entries be resolved?
     */
    private boolean resolveTxt;

    /**
     * Shall the MX-Entries be resolved?
     */
    private boolean resolveMx;

    /**
     * Shall the SenderScore entries be resolved?
     */
    private boolean resolveScore;

    /**
     * Shall WHOIS entries be resolved?
     */
    private boolean resolveWhois;

    /**
     * List of EMxOption constants for MX queries.
     */
    private List<EMxOption> mxOptionList;

    /**
     * List of EDnsOption constants for WHOIS queries.
     */
    private List<EDnsOption> whoisOptionList;

    /**
     * @param query The IP/Subnet/Domain for the queries.
     */
    public IpInfoOptions(final String query) {
        super();
        this.query = query.trim();
    }

    /**
     * Returns the value of resovleRdns.
     *
     * @return The value of resovleRdns.
     */
    public final boolean isResolveRdns() {
        return resolveRdns;
    }

    /**
     * Sets the value of resovleRdns.
     *
     * @param resovleRdns The value of resovleRdns.
     */
    public final void setResolveRdns(final boolean resovleRdns) {
        this.resolveRdns = resovleRdns;
    }

    /**
     * Returns the value of resolveTxt.
     *
     * @return The value of resolveTxt.
     */
    public final boolean isResolveTxt() {
        return resolveTxt;
    }

    /**
     * Sets the value of resolveTxt.
     *
     * @param resolveTxt The value of resolveTxt.
     */
    public final void setResolveTxt(final boolean resolveTxt) {
        this.resolveTxt = resolveTxt;
    }

    /**
     * Returns the value of resolveMx.
     *
     * @return The value of resolveMx.
     */
    public final boolean isResolveMx() {
        return resolveMx;
    }

    /**
     * Sets the value of resolveMx and a list of MX resolve options.
     *
     * @param resolveMx The value of resolveMx.
     * @param mxOptionList List of MX resolve options.
     */
    public final void setResolveMx(final boolean resolveMx, final List<EMxOption> mxOptionList) {
        this.resolveMx = resolveMx;
        this.mxOptionList = mxOptionList;
    }

    /**
     * Returns the value of mxOptionList.
     *
     * @return The value of mxOptionList.
     */
    public final List<EMxOption> getMxOptionList() {
        return mxOptionList;
    }

    /**
     * Returns the value of resolveScore.
     *
     * @return The value of resolveScore.
     */
    public final boolean isResolveScore() {
        return resolveScore;
    }

    /**
     * Returns the value of resolveWhois.
     *
     * @return The value of resolveWhois.
     */
    public final boolean isResolveWhois() {
        return resolveWhois;
    }

    /**
     * Sets the value of resolveWhois and a list of WHOIS resolve options.
     *
     * @param resolveWhois The value of resolveWhois.
     * @param whoisOptionList List of WHOIS resolve options.
     */
    public final void setResolveWhois(final boolean resolveWhois, final List<EDnsOption> whoisOptionList) {
        this.resolveWhois = resolveWhois;
        this.whoisOptionList = whoisOptionList;
    }

    /**
     * Returns the value of whoisOptionList.
     *
     * @return The value of whoisOptionList.
     */
    public final List<EDnsOption> getWhoisOptionList() {
        return whoisOptionList;
    }

    /**
     * Returns the value of query.
     *
     * @return The value of query.
     */
    public final String getQuery() {
        return query;
    }

}

