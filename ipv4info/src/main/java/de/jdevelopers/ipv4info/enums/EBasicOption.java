/*
* Copyright 2003, Carsten Jäger
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

package de.jdevelopers.ipv4info.enums;

/**
 * Enumeration of valid BasicResult-Options.
 *
 * @author Carsten JÃ¤ger (c.jaeger@jdevelopers.de)
 *
 */

public enum EBasicOption {

    /**
     * Netmask request.
     */
    NETMASK,
    /**
     * Address request.
     */
    ADDRESS,
    /**
     * Network request.
     */
    NETWORK,
    /**
     * Broadcast request.
     */
    BROADCAST,
    /**
     * Lowest address request.
     */
    LOW_ADDRESS,
    /**
     * Highest address request.
     */
    HIGH_ADDRESS,
    /**
     * CIDR request.
     */
    CIDR
}
