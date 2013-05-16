/*
* Copyright 2003, Carsten J�ger
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

package de.jdevelopers.ipv4info;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.objects.IpInfo;
import de.jdevelopers.ipv4info.objects.IpInfoOptions;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Klasse, die Informationen zu einer IPv4-Adresse, eines IPv4-Subnetzes oder einer Domain sammelt.
 * (IPv6 wird NICHT unterstützt!).
 *
 * Als Basis diente: http://www.java2s.com/Code/Java/Network-Protocol/
 * Aclassthatperformssomesubnetcalculationsgivenanetworkaddressandasubnetmask.htm
 *
 * Eine ähnliche Funktionalität wird vom Apache Commons-Net-Paket geboten, aber dafür müsste man ein JAR von ca. 262 KB
 * einbinden und das kann dann auch nicht mit IPv6 umgehen... :(
 *
 * Um Zusatzfunktionen wie das Holen von MX-/TXT-Einträgen zu erleichtern, wurde das dnsjava-Paket eingebunden.
 *
 * @version 0.5.0
 *
 */
public class Ipv4Info {

    /**
     * Shall MX entries be resolved?
     */
    private boolean resolveMx;

    /**
     * Shall SenderScore entries be resolved?
     */
    private boolean resolveScore;

    /**
     *  Shall RDNS entries be resolved?
     */
    private boolean resolveRdns;

    /**
     * Shall TXT entries be resolved?
     */
    private boolean resolveTxt;

    /**
     * List of EMxOption constants for MX queries.
     */
    private List<EMxOption> mxOptionList;

    /**
     * Constructor.
     */
    public Ipv4Info() {
    }

    /**
     * Constructor.
     *
     * @param query Query-String.
     */
    public Ipv4Info(final String query) {
        this(Arrays.asList(query));
    }

    /**
     * Constructor.
     *
     * @param queries List of Query-Strings.
     */
    public Ipv4Info(final List<String> queries) {
        addToQueries(false, queries);
    }

    /**
     * Enables/Dsiables all available resolving options.
     *
     * @param status {@code TRUE} to enable, {@code FALSE} to disable all resolve options.
     */
    public final void setAllResolveOptions(final boolean status) {
        setResolveMx(status, EMxOption.getDefaultOptions(false));
        setResolveRdns(status);
        setResolveTxt(status);
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
     * Returns the list with the MX options.
     *
     * If there was no MX resolve options given, the default options will take place.
     * The default options will remove MX pitfalls or doublet MX entries from the result.
     * To override this behaviour, set your own MX resolving options by calling
     * one of the setResolveMX() methods with the desired options.
     *
     * If you want to include pitfalls/doublets in your result, call one of the setResolveMx() methods
     * with an empty set of resolve options like this:
     *
     *      setResolveMx(true/false, new EMxOption[] {});
     * or
     *      setResolveMx(true/false, new ArrayList<EMxOption>());
     *
     * @return List with the MX options.
     */
    public final List<EMxOption> getMxOptions() {
        if (mxOptionList == null) {
            mxOptionList = new ArrayList<EMxOption>();
        }
        return mxOptionList;
    }

    /**
     * Sets the value of resolveMx.
     *
     * @param resolveMx The value of resolveMx.
     */
    public final void setResolveMx(final boolean resolveMx) {
        setResolveMx(resolveMx, getMxOptions());
    }

    /**
     * Sets the value of resolveMx and adds one or many EMxOptions for the request.
     *
     * @param resolveMx The value of resolveMx.
     * @param mxOptions One or many EMxOptions for the request.
     */
    public final void setResolveMx(final boolean resolveMx, final EMxOption... mxOptions) {
        setResolveMx(resolveMx, new ArrayList<EMxOption>(Arrays.asList(mxOptions)));
    }

    /**
     * Sets the value of resolveMx and adds a list of EMxOptions for the request.
     *
     * @param resolveMx The value of resolveMx.
     * @param mxOptionList List of EMxOptions for the request.
     */
    public final void setResolveMx(final boolean resolveMx, final List<EMxOption> mxOptionList) {
        this.resolveMx = resolveMx;
        this.mxOptionList = mxOptionList;
        if (this.mxOptionList == null) {
            getMxOptions();
        }
        if (this.resolveMx) {
            addToQueries(Ipv4Utils.getUnresolvedRequestsFromResultPool(EDnsOption.MX, this.mxOptionList));
        }
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
     * @return Returns the value of resolveRdns.
     */
    public final boolean isResolveRdns() {
        return resolveRdns;
    }

    /**
     * @param resolveRdns Sets the value of resolveRdns.
     */
    public final void setResolveRdns(final boolean resolveRdns) {
        this.resolveRdns = resolveRdns;
        if (this.resolveRdns) {
            addToQueries(Ipv4Utils.getUnresolvedRequestsFromResultPool(EDnsOption.RDNS, null));
        }
    }

    /**
     * @return Returns the value of resolveTxt.
     */
    public final boolean isResolveTxt() {
        return resolveTxt;
    }

    /**
     * @param resolveTxt Sets the value of resolveTxt.
     */
    public final void setResolveTxt(final boolean resolveTxt) {
        this.resolveTxt = resolveTxt;
        if (this.resolveTxt) {
            addToQueries(Ipv4Utils.getUnresolvedRequestsFromResultPool(EDnsOption.TXT, null));
        }
    }

    /**
     * Sets the number of retries for the resolver.
     *
     * @param retries Number of retries for the resolver.
     */
    public final void setResolverRetries(final int retries) {
        Ipv4Utils.setResolverRetries(retries);
    }

    /**
     * Adds on ore more queries to the internal result pool.
     * To get the best performance for adding queries, set the resolve options like MX, RDNS etc. AFTER calling addQueries()!
     *
     * @param queries One or more queries.
     */
    public final void addQueries(final String... queries) {
        addToQueries(false, Arrays.asList(queries));
    }

    /**
     * Adds a collection of queries to the internal result pool.
     * To get the best performance for adding queries, set the resolve options like MX, RDNS etc. AFTER calling addQueries()!
     *
     * @param queries One or more queries.
     */
    public final void addQueries(final Collection<String> queries) {
        addToQueries(false, queries);
    }

    /**
     * Adds queries to the internal result pool.
     * Just used internally when setting ANY resolve option AFTER adding the queries!
     *
     * @param ipInfoList List of IpInfo objects.
     */
    private void addToQueries(final List<IpInfo> ipInfoList) {
        if (ipInfoList == null || ipInfoList.isEmpty()) {
            return;
        }
        for (IpInfo ipInfo : ipInfoList) {
            ipInfo.resolveMissingResults(ipInfo.getIpInfoOptions());
        }
    }

    /**
     * Adds a collection of queries to the internal result pool.
     *
     * @param queriesAlreadyCorrected Are the query strings already corrected by the Ipv4Utils.getCorrectedQuery() function?
     * @param queries Collection of queries.
     */
    private void addToQueries(final boolean queriesAlreadyCorrected, final Collection<String> queries) {
        if (queries == null || queries.isEmpty()) {
            return;
        }
        synchronized (Ipv4Utils.RESULT_POOL) {
            for (final String query : queries) {
                final String correctedQuery = queriesAlreadyCorrected ? query : Ipv4Utils.getCorrectedQuery(query);
                if (correctedQuery != null && correctedQuery.length() > 0) {
                    IpInfo ipInfo = Ipv4Utils.RESULT_POOL.get(correctedQuery);
                    IpInfoOptions ipInfoOptions;
                    if (ipInfo != null) {
                        ipInfoOptions = ipInfo.getIpInfoOptions();
                    } else {
                        ipInfoOptions = new IpInfoOptions(correctedQuery);
                    }
                    ipInfoOptions.setResolveMx(isResolveMx(), getMxOptions());
                    ipInfoOptions.setResolveRdns(isResolveRdns());
                    ipInfoOptions.setResolveTxt(isResolveTxt());
                    if (ipInfo == null) {
                        Ipv4Utils.RESULT_POOL.put(correctedQuery, new IpInfo(query, ipInfoOptions));
                    } else {
                        // Check for paritially missing results.
                        Ipv4Utils.RESULT_POOL.get(correctedQuery).resolveMissingResults(ipInfoOptions);
                    }
                }
            }
            Ipv4Utils.RESULT_POOL.notifyAll();
        }
    }

    /**
     * Returns the results for the given queries.
     *
     * @param queries One or more queries.
     * @return Collection of IpInfo-Object's or null.
     */
    public final Collection<IpInfo> getResults(final String... queries) {
        return getResults(Arrays.asList(queries));
    }

    /**
     * Returns the results for the given queries.
     *
     * @param queries Collection of queries.
     * @return Collection of IpInfo-Object's or null.
     */
    public final Collection<IpInfo> getResults(final Collection<String> queries) {
        if (queries == null || queries.isEmpty()) {
            return null;
        }
        final List<IpInfo> result = new ArrayList<IpInfo>();
        for (final String query : queries) {
            if (query != null && query.length() > 0) {
                result.add(getResult(query));
            }
        }
        return result;
    }

    /**
     * Returns the result for the given query.
     *
     * @param query Query.
     * @return IpInfo-Object or null.
     */
    public final IpInfo getResult(final String query) {
        if (query == null || query.length() == 0) {
            return null;
        }
        final String correctedQuery = Ipv4Utils.getCorrectedQuery(query);
        if (!Ipv4Utils.RESULT_POOL.containsKey(correctedQuery)) {
            System.err.println("No pre-resolved query found. Creating new query for: " + query);
            addToQueries(true, Arrays.asList(correctedQuery));
        }
        final IpInfo result = Ipv4Utils.RESULT_POOL.get(correctedQuery);
        while (!result.isRequestDone()) {
            try {
                Thread.sleep(Ipv4Utils.CONST_20);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        result.setLastAccessed(System.currentTimeMillis());
        return result;
    }

}
