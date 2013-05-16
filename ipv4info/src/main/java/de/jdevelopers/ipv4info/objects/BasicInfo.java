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
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import de.jdevelopers.ipv4info.enums.EBasicOption;
import de.jdevelopers.ipv4info.resolvers.BasicResolver;
import de.jdevelopers.ipv4info.results.BasicResult;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Object that holds the basic informations for a given IP/Subnet/Hostname.
 *
 * @author Carsten Jäger
 *
 */

public class BasicInfo implements Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -2874043987002201011L;

    /**
     * The original query string.
     */
    private String originalQuery;

    /**
     * The corrected query string.
     */
    private String correctedQuery;

    /**
     * Resolved Netmask as String.
     */
    private String netmask = "";

    /**
     * Resolved IP-Address as String.
     */
    private String address = "";

    /**
     * Resolved Network-Address as String.
     */
    private String network = "";

    /**
     * Resolved Broadcast-Address as String.
     */
    private String broadcast = "";

    /**
     * Resolved lowest usable IP-Address as String.
     */
    private String lowAddress = "";

    /**
     * Resolved highest usable IP-Address as String.
     */
    private String highAddress = "";

    /**
     * IP-Address in CIDR-Notation.
     */
    private String cidrNotation = "";

    /**
     * Number of usable IP-Addresses.
     */
    private int usableAddressCount = -1;

    /**
     * List of usable IP-Addresses.
     */
    private List<String> usableAddresses;

    /**
     * Object, that holds the basic result values.
     */
    private BasicResult basicResult = new BasicResult();

    /**
     * Constructor.
     *
     * @param originalQuery Original query.
     * @param correctedQuery Corrected Query.
     */
    public BasicInfo(final String originalQuery, final String correctedQuery) {
        this.originalQuery = originalQuery;
        this.correctedQuery = correctedQuery;
        if (Ipv4Utils.isDnsjavaAvailable() && this.correctedQuery != null && this.correctedQuery.length() > 0) {
            Ipv4Utils.getThreadPool().execute(new BasicResolver(this.correctedQuery, basicResult));
        } else {
            basicResult.setBasicDone(true);
            if (!Ipv4Utils.isDnsjavaAvailable()) {
                basicResult.setIsResolvable(false);
            }
        }
    }

    /**
     * Returns the result of a given EBasicRequest-Type.
     *
     * @param requestOption EBasicRequest-Type.
     * @return Resulting string.
     */
    private String getBasicResult(final EBasicOption requestOption) {
        while (!basicResult.isBasicDone()) {
            try {
                Thread.sleep(Ipv4Utils.CONST_20);
            } catch (InterruptedException e) {
                e.printStackTrace();
                return null;
            }
        }
        if (requestOption == null) {
            return null;
        }
        switch (requestOption) {
        case NETMASK:
            return basicResult.isResolvable() ? (basicResult.isSubnet() ? Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(basicResult.getIntNetmask()),
                    false) : null) : null;
        case ADDRESS:
            return basicResult.isResolvable() ? Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(basicResult.getIntAddress()), false) : null;
        case NETWORK:
            return basicResult.isResolvable() ? (basicResult.isSubnet() ? Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(basicResult.getIntNetwork()),
                    false) : null) : null;
        case BROADCAST:
            return basicResult.isResolvable() ? (basicResult.isSubnet() ? Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(basicResult.getIntBroadcast()),
                    false) : null) : null;
        case LOW_ADDRESS:
            return basicResult.isResolvable() ? (basicResult.isSubnet() ? Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(getIntLowAddress()), false)
                    : null) : null;
        case HIGH_ADDRESS:
            return basicResult.isResolvable() ? (basicResult.isSubnet() ? Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(getIntHighAddress()), false)
                    : null) : null;
        case CIDR:
            return basicResult.isResolvable() ? isSubnet() ? Ipv4Utils.toCidrAddress(Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(
                    basicResult.getIntAddress()), false), Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(basicResult.getIntNetmask()), false))
                    : Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(basicResult.getIntAddress()), false) + "/" + (Ipv4Utils.CONST_30 + 1) : null;
        default:
            return null;
        }
    }

    /**
     * Returns the corrected query string.
     *
     * @return Corrected query string.
     */
    public final String getCorrectedQuery() {
        return correctedQuery;
    }

    /**
     * Returns the value of originalQuery.
     *
     * @return The value of originalQuery.
     */
    public final String getOriginalQuery() {
        return originalQuery;
    }

    /**
     * Returns the resolved netmask as int.
     *
     * @return Resolved Netmask as int.
     */
    public final int getIntNetmask() {
        getBasicResult(null);
        return basicResult.getIntNetmask();
    }

    /**
     * Returns the resolved netmask as IP-Address.
     *
     * @return Resolved Netmask as String.
     */
    public final String getNetmask() {
        if (netmask == null) {
            return null;
        } else if (netmask.equals("")) {
            netmask = getBasicResult(EBasicOption.NETMASK);
        }
        return netmask;
    }

    /**
     * Returns the resolved IP-Address as int.
     *
     * @return Resolved IP-Address as int.
     */
    public final int getIntAddress() {
        getBasicResult(null);
        return basicResult.getIntAddress();
    }

    /**
     * Returns the resolved IP-Address as IP-Address.
     *
     * @return Resolved IP-Address as String.
     */
    public final String getAddress() {
        if (address == null) {
            return null;
        } else if (address.equals("")) {
            address = getBasicResult(EBasicOption.ADDRESS);
        }
        return address;
    }

    /**
     * Returns the resolved Network-Address as int.
     *
     * @return Resolved Network-Address as int.
     */
    public final int getIntNetwork() {
        getBasicResult(null);
        return basicResult.getIntNetwork();
    }

    /**
     * Returns the resolved Network-Address as IP-Address.
     *
     * @return Resolved Network-Address as String.
     */
    public final String getNetwork() {
        if (network == null) {
            return null;
        } else if (network.equals("")) {
            network = getBasicResult(EBasicOption.NETWORK);
        }
        return network;
    }

    /**
     * Returns the resolved Broadcast-Address as int.
     *
     * @return Resolved Broadcast-Address as int.
     */
    public final int getIntBroadcast() {
        getBasicResult(null);
        return basicResult.getIntBroadcast();
    }

    /**
     * Returns the resolved Broadcast-Address as IP-Address.
     *
     * @return Resolved Broadcast-Address as String.
     */
    public final String getBroadcast() {
        if (broadcast == null) {
            return null;
        } else if (broadcast.equals("")) {
            broadcast = getBasicResult(EBasicOption.BROADCAST);
        }
        return broadcast;
    }

    /**
     * Returns the lowest resolved usable IP-Address as int.
     *
     * @return Lowest resolved usable IP-Address as int.
     */
    public final int getIntLowAddress() {
        getBasicResult(null);
        return isSubnet() ? getUsableAddressCount() > 0 ? basicResult.getIntNetwork() + 1 : 0 : 0;
    }

    /**
     * Returns the lowest resolved usable IP-Address as String.
     *
     * @return Lowest resolved usable IP-Address as String.
     */
    public final String getLowAddress() {
        if (lowAddress == null) {
            return null;
        } else if (lowAddress.equals("")) {
            lowAddress = getBasicResult(EBasicOption.LOW_ADDRESS);
        }
        return lowAddress;
    }

    /**
     * Returns the highest resolved usable IP-Address as int.
     *
     * @return Highest resolved usable IP-Address as int.
     */
    public final int getIntHighAddress() {
        getBasicResult(null);
        return isSubnet() ? getUsableAddressCount() > 0 ? basicResult.getIntBroadcast() - 1 : 0 : 0;
    }

    /**
     * Returns the highest resolved usable IP-Address as String.
     *
     * @return Highest resolved usable IP-Address as String.
     */
    public final String getHighAddress() {
        if (highAddress == null) {
            return null;
        } else if (highAddress.equals("")) {
            highAddress = getBasicResult(EBasicOption.HIGH_ADDRESS);
        }
        return highAddress;
    }

    /**
     * Returns the CIDR-Notation of address.
     *
     * @return CIDR-Notation of address.
     */
    public final String getCidrNotation() {
        if (cidrNotation == null) {
            return null;
        } else if (cidrNotation.equals("")) {
            cidrNotation = getBasicResult(EBasicOption.CIDR);
        }
        return cidrNotation;
    }

    /**
     * Returns the number of usable IP-Addresses of a subnet or 1 if the query is a simple
     * IP or hostname.
     *
     * @return Number of usable IP-Addresses.
     */
    public final int getUsableAddressCount() {
        getBasicResult(null);
        if (basicResult.isResolvable()) {
            if (usableAddressCount < 0) {
                if (isSubnet()) {
                    usableAddressCount = basicResult.getIntBroadcast() - (basicResult.getIntNetwork() + 1);
                } else {
                    usableAddressCount = 1;
                }
                if (usableAddressCount < 0) {
                    usableAddressCount = 0;
                }
            }
            return usableAddressCount;
        } else {
            return 0;
        }
    }

    /**
     * Returns a list of usable IP-Addresses.
     *
     * @return List of usable IP-Addresses.
     */
    public final Collection<String> getUsableAddresses() {
        if (usableAddresses != null) {
            return usableAddresses;
        }
        usableAddresses = Collections.synchronizedList(new ArrayList<String>());
        if (isSubnet()) {
            for (int subIp = (getIntNetwork() + 1); subIp <= (getIntBroadcast() - 1); ++subIp) {
                usableAddresses.add(Ipv4Utils.formatToIp(Ipv4Utils.intToShortList(subIp), false));
            }
        } else {
            usableAddresses.add(getAddress());
        }
        return usableAddresses;
    }

    /**
     * Is the incoming query string a simple IP-Address?
     *
     * @return {@code TRUE} if it is a simple IP-Address, otherwise {@code FALSE}.
     */
    public final boolean isIp() {
        getBasicResult(null);
        return basicResult.isIp();
    }

    /**
     * Is the incoming query string a subnet?
     *
     * @return {@code TRUE} if it is a subnet, otherwise {@code FALSE}.
     */
    public final boolean isSubnet() {
        getBasicResult(null);
        return basicResult.isSubnet();
    }

    /**
     * Is the incoming query string a domain?
     *
     * @return {@code TRUE} if it's a domain, otherwise {@code FALSE}.
     */
    public final boolean isDomain() {
        getBasicResult(null);
        return basicResult.isDomain();
    }

    /**
     * Is the incoming query a resovalbe Address?
     *
     * @return Returns the value of isResolvable.
     */
    public final boolean isResolvable() {
        getBasicResult(null);
        return basicResult.isResolvable();
    }

    /**
     * Is the init procedure done?
     *
     * @return Returns the value of basicResult.basicDone.
     */
    public final boolean isBasicDone() {
        return basicResult.isBasicDone();
    }

    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((basicResult == null) ? 0 : basicResult.hashCode());
        result = prime * result + ((correctedQuery == null) ? 0 : correctedQuery.hashCode());
        result = prime * result + ((originalQuery == null) ? 0 : originalQuery.hashCode());
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
        BasicInfo other = (BasicInfo) obj;
        if (basicResult == null) {
            if (other.basicResult != null) {
                return false;
            }
        } else if (!basicResult.equals(other.basicResult)) {
            return false;
        }
        if (correctedQuery == null) {
            if (other.correctedQuery != null) {
                return false;
            }
        } else if (!correctedQuery.equals(other.correctedQuery)) {
            return false;
        }
        if (originalQuery == null) {
            if (other.originalQuery != null) {
                return false;
            }
        } else if (!originalQuery.equals(other.originalQuery)) {
            return false;
        }
        return true;
    }

}
