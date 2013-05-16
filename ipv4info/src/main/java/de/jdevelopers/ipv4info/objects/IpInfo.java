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

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.resolvers.MxResolver;
import de.jdevelopers.ipv4info.resolvers.RdnsResolver;
import de.jdevelopers.ipv4info.resolvers.TxtResolver;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Object that holds all the informations for a given IP/Subnet/Hostname.
 *
 * @author Carsten Jäger
 *
 */
public class IpInfo extends BasicInfo implements Comparable<IpInfo>, Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -1771327865767732883L;

    /*
     * Running states. Declared as transient to exclude from serialization.
     */

    /**
     * Is there a MX runner in progress?
     */
    private transient boolean mxRunning;

    /**
     * Finish status of the MX request (including retry).
     */
    private transient boolean isMxDone;

    /**
     * Is there a RDNS runner in progress?
     */
    private transient boolean rdnsRunning;

    /**
     * Is there a TXT runner in progress?
     */
    private transient boolean txtRunning;

    /**
     * IpInfoOptions-Object.
     */
    private IpInfoOptions ipInfoOptions;

    /**
     * When was this object was last accessed?
     */
    private long lastAccessed;

    /**
     * MXInfo Result.
     */
    private MxInfo mxInfo;

    /**
     * RDNS Result.
     */
    private RdnsInfo rdnsInfo;

    /**
     * TXT Result.
     */
    private TxtInfo txtInfo;

    /**
     * Retry MX resolve on error.
     */
    private boolean retryResolve;

    /**
     * Was there any further action performed rather than resolving the basics?
     * This flag is for the usage with the CacheRunner-Task only!
     */
    private boolean anyResolveActionPerformed;

    /**
     * Constructor.
     *
     * @param query Query string.
     * @param ipInfoOptions IpInfoOptions-Object.
     */
    public IpInfo(final String query, final IpInfoOptions ipInfoOptions) {
        super(query, ipInfoOptions.getQuery());
        this.ipInfoOptions = ipInfoOptions;
        resolveMissingResults(ipInfoOptions);
    }

    /**
     * Checks avalability of desired results and starts the belonging tasks if result is missing.
     *
     * @param ipInfoOptions IpInfoOptions-Object.
     */
    public final void resolveMissingResults(final IpInfoOptions ipInfoOptions) {
        if (ipInfoOptions == null) {
            setMxDone(true);
            setRunning(false, EDnsOption.MX);
            setRunning(false, EDnsOption.RDNS);
            setRunning(false, EDnsOption.TXT);
            anyResolveActionPerformed = false;
            return;
        }
        /*
         * The order of the tasks is arbitrary. But the order below is optimized for speed, because some results
         * depends on others. If the depended task is started some milliseconds earlier it can reduce the waittime.
         * So the overall speed could be a little bit better. For just one ore two requests it makes no real
         * difference, but if if you make dozens or hundreds of parallel requests it can summarize to remarkable values...
         */
        // Check for the need to run a MX task.
        if (ipInfoOptions.isResolveMx()) {
            if (mxInfo == null) {
                mxInfo = new MxInfo(getCorrectedQuery(), this);
            }
            if (isSubnet()) {
                // For subnet queries a MX request isn't possible!
                setRunning(false, EDnsOption.MX);
                setMxDone(true);
            } else if (!isRunning(EDnsOption.MX) && !isMxDone()) {
                anyResolveActionPerformed = true;
                Ipv4Utils.getThreadPool().execute(new MxResolver(this, false));
            }
        } else {
            setRunning(false, EDnsOption.MX);
            setMxDone(true);
        }
        // Check for the need to run a RDNS task.
        if (!isRunning(EDnsOption.RDNS) && ipInfoOptions.isResolveRdns()) {
            if (rdnsInfo == null) {
                rdnsInfo = new RdnsInfo(getCorrectedQuery(), this);
            }
            setRunning(true, EDnsOption.RDNS);
            anyResolveActionPerformed = true;
            Ipv4Utils.getThreadPool().execute(new RdnsResolver(this));
        }
        // Check for the need to run a TXT task.
        if (!isRunning(EDnsOption.TXT) && ipInfoOptions.isResolveTxt()) {
            if (txtInfo == null) {
                txtInfo = new TxtInfo(getCorrectedQuery(), this);
            }
            setRunning(true, EDnsOption.TXT);
            anyResolveActionPerformed = true;
            Ipv4Utils.getThreadPool().execute(new TxtResolver(this));
        }
        //Additional Tasks...?!
    }

    /**
     * @return Returns the value of ipInfoOptions.
     */
    public final IpInfoOptions getIpInfoOptions() {
        return ipInfoOptions;
    }

    /**
     * @return Returns the value of mxInfo.
     */
    public final MxInfo getMxInfo() {
        if (!ipInfoOptions.isResolveMx()) {
            ipInfoOptions.setResolveMx(true, EMxOption.getDefaultOptions(false));
            setMxDone(false);
            resolveMissingResults(ipInfoOptions);
            while (!isMxDone()) {
                try {
                    Thread.sleep(Ipv4Utils.CONST_20);
                } catch (InterruptedException ie) {
                    break;
                }
            }
        }
        return mxInfo;
    }

    /**
     * Returns the value of rdnsInfo.
     *
     * @return The value of rdnsInfo.
     */
    public final RdnsInfo getRdnsInfo() {
        if (!ipInfoOptions.isResolveRdns()) {
            ipInfoOptions.setResolveRdns(true);
            resolveMissingResults(ipInfoOptions);
            while (isRunning(EDnsOption.RDNS)) {
                try {
                    Thread.sleep(Ipv4Utils.CONST_20);
                } catch (InterruptedException ie) {
                    break;
                }
            }
        }
        return rdnsInfo;
    }

    /**
     * Returns the value of txtInfo.
     *
     * @return The value of txtInfo.
     */
    public final TxtInfo getTxtInfo() {
        if (!ipInfoOptions.isResolveTxt()) {
            ipInfoOptions.setResolveTxt(true);
            resolveMissingResults(ipInfoOptions);
            while (isRunning(EDnsOption.TXT)) {
                try {
                    Thread.sleep(Ipv4Utils.CONST_20);
                } catch (InterruptedException ie) {
                    break;
                }
            }
        }
        return txtInfo;
    }

    /**
     * Set the running status of the given request type.
     *
     * @param status Status.
     * @param option EDnsOption request tpye.
     */
    public final void setRunning(final boolean status, final EDnsOption option) {
        switch (option) {
        case MX: mxRunning = status; break;
        case RDNS: rdnsRunning = status; break;
        case TXT: txtRunning = status; break;
        default: break;
        }
    }

    /**
     * Returns the running status of the given request type.
     *
     * @param option EDnsOption request type.
     * @return Running status of the given request type.
     */
    public final boolean isRunning(final EDnsOption option) {
        switch (option) {
        case MX: return mxRunning;
        case RDNS: return rdnsRunning;
        case TXT: return txtRunning;
        default: return false;
        }
    }

    /**
     * @return Returns the value of isMxDone.
     */
    public final boolean isMxDone() {
        return isMxDone;
    }

    /**
     * @param isMxDone Sets the value of isMxDone.
     */
    public final void setMxDone(final boolean isMxDone) {
        if (ipInfoOptions.getMxOptionList().contains(EMxOption.RETRY)) {
            if (isRetryResolve()) {
                this.isMxDone = false;
                Ipv4Utils.getRecheckThreadPool().execute(new MxResolver(this, true));
            } else {
                this.isMxDone = isMxDone;
            }
        } else {
            this.isMxDone = isMxDone;
        }
    }

    /**
     * Returns the state of running requests (if any).
     *
     * @return Returns {@code TRUE}, if all requests are finished, otherwise {@code FALSE}.
     */
    public final boolean isRequestDone() {
//        System.err.println("######## Status for: " + getCorrectedQuery() + " ########");
//        System.err.println("isBasicDone: " + isBasicDone());
//        System.err.println("isMxRunning: " + isMxRunning());
//        System.err.println("isMxDone: " + isMxDone());
//        System.err.println("isRdnsRunning: " + isRdnsRunning());
//        System.err.println("isTxtRunning: " + isTxtRunning());
        return isBasicDone() && isMxDone() && !isRunning(EDnsOption.MX) && !isRunning(EDnsOption.RDNS) && !isRunning(EDnsOption.TXT);
    }

    /**
     * Returns the value of lastAccessed.
     *
     * @return The value of lastAccessed.
     */
    public final long getLastAccessed() {
        return lastAccessed;
    }

    /**
     * Sets the value of lastAccessed.
     *
     * @param lastAccessed The value of lastAccessed.
     */
    public final void setLastAccessed(final long lastAccessed) {
        this.lastAccessed = lastAccessed;
    }

    /**
     * @return Returns the value of retryResolve.
     */
    public final boolean isRetryResolve() {
        return retryResolve;
    }

    /**
     * @param retryResolve Sets the value of retryResolve.
     */
    public final void setRetryResolve(final boolean retryResolve) {
        this.retryResolve = retryResolve;
    }

    /**
     * Returns the value of anyResolveActionPerformed.
     *
     * @return The value of anyResolveActionPerformed.
     */
    public final boolean isAnyResolveActionPerformed() {
        return anyResolveActionPerformed;
    }

    public final int compareTo(final IpInfo ipInfo) {
        return getCorrectedQuery().compareTo(ipInfo.getCorrectedQuery());
    }

    @Override
    public final String toString() {
       final StringBuilder sb = new StringBuilder(Ipv4Utils.DIVIDER);
       sb.append("BASIC info for \"").append(getOriginalQuery()).append("\":\n").append(Ipv4Utils.DIVIDER);
       // Basic info's.
       sb.append("Autocorrected Query          : ").append(getCorrectedQuery()).append("\n")
         .append("Query is Domain              : ").append(isDomain()).append("\n")
         .append("Query is Subnet              : ").append(isSubnet()).append("\n")
         .append("Query is IP                  : ").append(isIp()).append("\n")
         .append("Query is resolvable          : ").append(isResolvable()).append("\n");
//       sb.append("CIDR-Notation                : ").append(getCidrNotation()).append("\n");
       sb.append("IP-Address                   : ").append(getAddress()).append("\n")
         .append("Netmask                      : ").append(getNetmask()).append("\n")
         .append("Network-Address              : ").append(getNetwork()).append("\n")
         .append("Broadcast-Address            : ").append(getBroadcast()).append("\n")
         .append("Lowest usable Address        : ").append(getLowAddress()).append("\n")
         .append("Highest usable Address       : ").append(getHighAddress()).append("\n")
         .append("Usable Addresses             : ").append(getUsableAddressCount()).append("\n")
         .append("IP-Address             (int) : ").append(getIntAddress()).append("\n")
         .append("Netmask                (int) : ").append(getIntNetmask()).append("\n")
         .append("Network-Address        (int) : ").append(getIntNetwork()).append("\n")
         .append("Broadcast-Address      (int) : ").append(getIntBroadcast()).append("\n")
         .append("Lowest usable Address  (int) : ").append(getIntLowAddress()).append("\n")
         .append("Highest usable Address (int) : ").append(getIntHighAddress()).append("\n");
       //sb.append("Any action performed         : ").append(anyResolveActionPerformed).append("\n");
       // MX info's.
       if (ipInfoOptions.isResolveMx()) {
           sb.append(getMxInfo());
       }
       // RDNS info's.
       if (ipInfoOptions.isResolveRdns()) {
           sb.append(getRdnsInfo());
       }
       // TXT info's.
       if (ipInfoOptions.isResolveTxt()) {
           sb.append(getTxtInfo());
       }
       return sb.toString();
   }

}
