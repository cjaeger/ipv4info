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

/**
 * Result-Object for Basic IP-Calls.
 *
 * @author Carsten Jäger
 *
 */
public class BasicResult implements Cloneable, Serializable {

    /**
     * Serialization-Id.
     */
    private static final long serialVersionUID = -3489704328141009698L;

    /**
     * Resolved Netmask as int.
     */
    private int intNetmask;

    /**
     * Resolved IP-Address as int.
     */
    private int intAddress;

    /**
     * Resolved Network-Address as int.
     */
    private int intNetwork;

    /**
     * Resolved Broadcast-Address as int.
     */
    private int intBroadcast;

    /**
     * Is the query a resolvable Address?
     */
    private boolean isResolvable = true;

    /**
     * Is the incoming query a simple IP?
     */
    private boolean isIp;

    /**
     * Is the incoming query a subnet?
     */
    private boolean isSubnet;

    /**
     * Is the incoming query a domain?
     */
    private boolean isDomain;

    /**
     * Are all the values set?
     */
    private boolean isBasicDone;

    /**
     * Was there an invalid subnet query?
     */
    private boolean invalidSubnet;

    /**
     * @return Returns the value of intNetmask.
     */
    public final int getIntNetmask() {
        return intNetmask;
    }

    /**
     * @param intNetmask Sets the value of intNetmask.
     */
    public final void setIntNetmask(final int intNetmask) {
        this.intNetmask = intNetmask;
    }

    /**
     * @return Returns the value of intAddress.
     */
    public final int getIntAddress() {
        return intAddress;
    }

    /**
     * @param intAddress Sets the value of intAddress.
     */
    public final void setIntAddress(final int intAddress) {
        this.intAddress = intAddress;
    }

    /**
     * @return Returns the value of intNetwork.
     */
    public final int getIntNetwork() {
        return intNetwork;
    }

    /**
     * @param intNetwork Sets the value of intNetwork.
     */
    public final void setIntNetwork(final int intNetwork) {
        this.intNetwork = intNetwork;
    }

    /**
     * @return Returns the value of intBroadcast.
     */
    public final int getIntBroadcast() {
        return intBroadcast;
    }

    /**
     * @param intBroadcast Sets the value of intBroadcast.
     */
    public final void setIntBroadcast(final int intBroadcast) {
        this.intBroadcast = intBroadcast;
    }

    /**
     * @return Returns the value of isResolvable.
     */
    public final boolean isResolvable() {
        return isResolvable;
    }

    /**
     * @param isResolvable Sets the value of isResolvable.
     */
    public final void setIsResolvable(final boolean isResolvable) {
        this.isResolvable = isResolvable;
    }

    /**
     * @return Returns the value of isIp.
     */
    public final boolean isIp() {
        return isIp;
    }

    /**
     * @param isIp Sets the value of isIp.
     */
    public final void setIsIp(final boolean isIp) {
        this.isIp = isIp;
    }

    /**
     * @return Returns the value of isSubnet.
     */
    public final boolean isSubnet() {
        return isSubnet;
    }

    /**
     * @param isSubnet Sets the value of isSubnet.
     */
    public final void setIsSubnet(final boolean isSubnet) {
        this.isSubnet = isSubnet;
    }

    /**
     * @return Returns the value of isDomain.
     */
    public final boolean isDomain() {
        return isDomain;
    }

    /**
     * @param isDomain Sets the value of isDomain.
     */
    public final void setIsDomain(final boolean isDomain) {
        this.isDomain = isDomain;
    }

    /**
     * Returns the value of invalidSubnet.
     *
     * @return The value of invalidSubnet.
     */
    public final boolean isInvalidSubnet() {
        return invalidSubnet;
    }

    /**
     * Sets the value of invalidSubnet.
     *
     * @param invalidSubnet The value of invalidSubnet.
     */
    public final void setInvalidSubnet(final boolean invalidSubnet) {
        this.invalidSubnet = invalidSubnet;
    }

    /**
     * @return Returns the value of initDone.
     */
    public final boolean isBasicDone() {
        return isBasicDone;
    }

    /**
     * @param basicDone Sets the value of basicDone.
     */
    public final void setBasicDone(final boolean basicDone) {
        this.isBasicDone = basicDone;
    }

    @Override
    public final int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + intAddress;
        result = prime * result + intBroadcast;
        result = prime * result + intNetmask;
        result = prime * result + intNetwork;
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
        BasicResult other = (BasicResult) obj;
        if (intAddress != other.intAddress || intBroadcast != other.intBroadcast || intNetmask != other.intNetmask
                || intNetwork != other.intNetwork) {
            return false;
        }
        return true;
    }

}
