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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import de.jdevelopers.ipv4info.enums.EException;
import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.results.MxResult;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Object that holds the MX summary.
 *
 * @author Carsten Jäger
 *
 */
public class MxInfo implements Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = 7383366656004787559L;

    /**
     * Internal map that holds all MxResults ordered by their priority.
     *
     * A TreeMap is used to allow getting MxResult-Objects in a specific
     * priority range by getting just a submap from mxResultMap.
     */
    private TreeMap<Integer, List<MxResult>> mxResultMap = new TreeMap<Integer, List<MxResult>>();

    /**
     * Internal used HashSet to avoid adding doublette MX domains.
     *
     * Sounds a little bit senseless? No, here's a sample:
     *
     * Resolving the domain "bridge-holding.ru" for MX entries will give you the following (using nslookup on Windows):
     *
     * bridge-holding.ru       MX preference = 100, mail exchanger = 148.240.4.32
     * bridge-holding.ru       MX preference =  10, mail exchanger = 148.240.4.32
     *
     * As you can see, there are two MX entries, but both are the same, just the priority differs.
     * But the best is: They won't answer on connections ("telnet 148.240.4.32 25" will end with a connection timeout)!
     *
     * If you implement your own MTA (MailTransferAgent), you will normally do the following steps:
     *
     * 1. Connect to the address with the lowest priority.
     * 2. On any error (here it will be SocketTimeoutException), try the next available address with a higher priority.
     *
     * As both are the sames addresses, it will double up the time before you recognize, that you can't send any mails
     * to this address! So it generally makes sense, to avoid doublette entries...
     *
     */
    private Set<String> alreadyAddedSet = new HashSet<String>();

    /**
     * Request exception.
     */
    private EException requestException = EException.NONE;

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
    public MxInfo(final String query, final IpInfo ipInfo) {
        super();
        this.query = query;
        this.ipInfo = ipInfo;
    }

    /**
     * @return Returns the value of query.
     */
    public final String getQuery() {
        return query;
    }

    /**
     * @return Returns the value of requestException.
     */
    public final EException getRequestException() {
        return requestException;
    }

    /**
     * @param requestException Sets the value of requestException.
     */
    public final void setRequestException(final EException requestException) {
        this.requestException = requestException;
    }

    /**
     * Adds a MxResult-Object to the internal result map.
     *
     * @param mxResult MxResult-Object.
     */
    public final void addToMxResultMap(final MxResult mxResult) {
        if (mxResult == null) {
            return;
        }
        // If no options are given, no pitfalls will be included in the result.
        if (ipInfo.getIpInfoOptions().getMxOptionList().isEmpty() && mxResult.isPitfall()) {
            return;
        }
        if (alreadyAddedSet.contains(mxResult.getDomain())) {
            if (ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.MARK_DOUBLETTES)) {
                mxResult.setDoublet(true);
                mxResult.setHasDoublet(true);
                try {
                    for (MxResult firstResult : getMxResult(true, false, false).values().iterator().next()) {
                        if (firstResult.getDomain().equals(mxResult.getDomain())) {
                            firstResult.setHasDoublet(true);
                            break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                // The default behaviour is NOT to return any doublets.
                return;
            }
        }
        List<MxResult> mxResultList = mxResultMap.get(mxResult.getPriority());
        if (mxResultList == null) {
            mxResultList = new ArrayList<MxResult>();
            mxResultList.add(mxResult);
        } else {
            if (mxResultList.contains(mxResult)) {
                // Merge two MxResult objects with same domains together:
                mxResultList.get(mxResultList.indexOf(mxResult)).addToMxIps(mxResult.getMxIps());
                mxResult.clear();
            } else {
                // Adding an MX entry with the same priority as another entry already had.
                mxResultList.add(mxResult);
            }
        }
        alreadyAddedSet.add(mxResult.getDomain());
        mxResultMap.put(mxResult.getPriority(), mxResultList);
    }

    /**
     * Returns an unmodified version of the MX result map.
     *
     * @return MX result map.
     */
    public final Map<Integer, List<MxResult>> getMxResult() {
        return getMxResult(false, false, false);
    }

    /**
     * Returns a modified version of the MX result map.
     *
     * @param mergePriorities Shall all found priorities merged into one priority?
     * @param useCopy Shall a copy of the MX result map beeing returned, or the original map?
     * @return MX result map.
     */
    public final Map<Integer, List<MxResult>> getMxResult(final boolean mergePriorities, final boolean useCopy) {
        return getMxResult(mergePriorities, false, false);
    }

    /**
     * Returns the MX results.
     *
     * @param mergePriorities Shall all found priorities merged into one priority?
     * @param skipDisabled Shall already disabled entries be removed from the result?
     * @param useCopy Shall a copy of the MX result map beeing returned, or the original map?
     * @return MX result map.
     */
    @SuppressWarnings("unchecked")
    public final Map<Integer, List<MxResult>> getMxResult(final boolean mergePriorities, final boolean skipDisabled, final boolean useCopy) {
        if (mxResultMap.isEmpty()) {
            return mxResultMap;
        }
        if (!mergePriorities && !skipDisabled) {
            // Returns a shallow, unmodified copy of mxResultMap, if a copy was requested.
            return useCopy ? (TreeMap<Integer, List<MxResult>>) mxResultMap.clone() : mxResultMap;
        }
        Map<Integer, List<MxResult>> result = null;
        Set<MxResult> mxResultList;
        if (mergePriorities) {
            mxResultList = new HashSet<MxResult>();
            final int mergedPriority = mxResultMap.firstKey();
            for (final int priority : mxResultMap.keySet()) {
                mxResultList.addAll(mxResultMap.get(priority));
            }
            if (useCopy) {
                result = new HashMap<Integer, List<MxResult>>();
                result.put(mergedPriority, new ArrayList<MxResult>(mxResultList));
            } else {
                mxResultMap.clear();
                mxResultMap.put(mergedPriority, new ArrayList<MxResult>(mxResultList));
                result = mxResultMap;
            }
            mxResultList.clear();
        } else {
            // Sets result to a shallow copy of mxResultMap, if a copy was requested.
            result = useCopy ? (TreeMap<Integer, List<MxResult>>) mxResultMap.clone() : mxResultMap;
        }
        if (skipDisabled) {
            final List<Integer> emptyPriorities = new ArrayList<Integer>();
            for (final int priority : result.keySet()) {
                mxResultList = new HashSet<MxResult>();
                for (final MxResult mxResult : result.get(priority)) {
                    if (mxResult.isDisabled()) {
                       mxResultList.add(mxResult);
                    }
                }
                result.get(priority).removeAll(mxResultList);
                if (result.get(priority).isEmpty()) {
                    emptyPriorities.add(priority);
                }
            }
            for (final int priority : emptyPriorities) {
                result.remove(priority);
            }
            emptyPriorities.clear();
        }
        return result;
    }

    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mxResultMap == null) ? 0 : mxResultMap.hashCode());
        result = prime * result + ((query == null) ? 0 : query.hashCode());
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
        MxInfo other = (MxInfo) obj;
        if (!mxResultMap.equals(other.mxResultMap)) {
            return false;
        }
        if (query == null) {
            if (other.query != null) {
                return false;
            }
        } else if (!query.equals(other.query)) {
            return false;
        }
        return true;
    }

    @Override
    public final String toString() {
        final StringBuilder sb = new StringBuilder(Ipv4Utils.DIVIDER);
        if (!getMxResult().isEmpty()) {
            sb.append("MX info for \"").append(query).append("\":\n");
            sb.append(Ipv4Utils.DIVIDER);
            int valueCount = 0;
            for (List<MxResult> mxResults : getMxResult().values()) {
                ++valueCount;
                int count = 0;
                for (MxResult mxResult : mxResults) {
                    sb.append(mxResult);
                    if (valueCount == getMxResult().size() && ++count == mxResults.size()) {
                        continue;
                    }
                    //sb.append(Ipv4Utils.DIVIDER);
                    sb.append("\n");
                }
            }
        } else {
            sb.append("MX info for \"").append(query).append("\" not");
            if (!ipInfo.isResolvable()) {
                if (ipInfo.isDomain()) {
                    sb.append(" possible (NXDOMAIN)");
                } else if (ipInfo.isIp()) {
                    sb.append(" possible (INVALIDIP)");
                }
            } else if (ipInfo.isSubnet()) {
                sb.append(" possible (SUBNET)");
            } else {
                sb.append(" available (NOMX)");
            }
            if (requestException != EException.NONE) {
                sb.append(" (Exception: ").append(requestException).append(")");
            }
            sb.append(".\n");
        }
        return sb.toString();
    }

}

