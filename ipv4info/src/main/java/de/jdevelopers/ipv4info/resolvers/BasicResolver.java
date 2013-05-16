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

package de.jdevelopers.ipv4info.resolvers;

import java.net.SocketTimeoutException;
import java.util.regex.Matcher;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import de.jdevelopers.ipv4info.results.BasicResult;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Thread for Basic IP-Lookups.
 *
 * @author Carsten JÃ¤ger (c.jaeger@jdevelopers.de)
 *
 */
public class BasicResolver implements Runnable {

    /**
     * The query.
     */
    private String query;

    /**
     * Resulting BasicResult-Object.
     */
    private BasicResult basicResult;

    /**
     * Constructor.
     *
     * @param query Query string.
     * @param basicResult Reference to the resulting BasicResult-Object.
     */
    public BasicResolver(final String query, final BasicResult basicResult) {
        this.query = query;
        this.basicResult = basicResult;
    }

    public final void run() {
        if (basicResult == null) {
            basicResult = new BasicResult();
        }
        if (query == null) {
            basicResult.setBasicDone(true);
            return;
        }
        try {
            Matcher matcher = Ipv4Utils.DOMAIN_PATTERN.matcher(query);
            if (matcher.find()) {
                basicResult.setIsDomain(true);
                // Change representation of query to a CIDR-Notation (Get A-Record)
                try {
                    query = getARecord(query, false);
                } catch (SocketTimeoutException ste) {
                    // Retry it with the recheckResolver from Ipv4Utils.
                    try {
                        query = getARecord(query, true);
                    } catch (Exception e) {
                        basicResult.setIsResolvable(false);
                        return;
                    }
                } catch (Exception e) {
                    basicResult.setIsResolvable(false);
                    return;
                }
            } else {
                if (Ipv4Utils.ADDRESS_PATTERN.matcher(query).find()) {
                    basicResult.setIsIp(true);
                    query += "/31";
                } else {
                    // Invalid IP-Address
                    matcher = Ipv4Utils.SIMPLE_IPS_PATTERN.matcher(query);
                    if (matcher.find()) {
                        if (matcher.group(2) != null) {
                            // Subnet (CIDR) notation
                            basicResult.setIsSubnet(true);
                            if (Integer.parseInt(matcher.group(2)) > Ipv4Utils.CONST_30 + 1) {
                                basicResult.setIsResolvable(false);
                                return;
                            }
                        } else {
                            // Simple IP notation
                            basicResult.setIsIp(true);
                            basicResult.setIsResolvable(false);
                            return;
                        }
                    }
                }
            }
            // Here the query should be represented in CIDR-Notation
            matcher = Ipv4Utils.CIDR_PATTERN.matcher(query);
            if (!matcher.find()) {
                basicResult.setIsResolvable(false);
                return;
            }
            basicResult.setIsSubnet(!(basicResult.isDomain() || basicResult.isIp()));
            basicResult.setIntAddress(Ipv4Utils.matchAddress(matcher));
            if (basicResult.isSubnet()) {
                byte cidr = Byte.parseByte(matcher.group(Ipv4Utils.CONST_5));
                /*
                 * cidr may not be less than 24 and not be greater than 31!
                 * There are values less than 24 possible, but this equals to resolve the half internet, so we deny it...
                 */
                if (cidr < Ipv4Utils.CONST_20 + Ipv4Utils.CONST_4 || cidr > Ipv4Utils.CONST_30 + 1) {
                    basicResult.setIsResolvable(false);
                    basicResult.setInvalidSubnet(true);
                    return;
                } else if (cidr < 0) {
                    cidr = 0;
                }
                int intNetmask = 0;
                for (byte i = 0; i < cidr; ++i) {
                    intNetmask |= (1 << (Ipv4Utils.CONST_30 + 1) - i);
                }
                basicResult.setIntNetmask(intNetmask);
                basicResult.setIntNetwork(basicResult.getIntAddress() & basicResult.getIntNetmask());
                basicResult.setIntBroadcast(basicResult.getIntNetwork() | ~basicResult.getIntNetmask());
            }
        } finally {
            basicResult.setBasicDone(true);
        }
    }

    /**
     * Returns the A-Record for a given domain.
     *
     * @param domain Domain.
     * @param useRecheckResolver {@code true} to use the recheckResolver from Ipv4Utils, otherwise {@code false}.
     * @return A-Record for the given domain.
     * @throws Exception Throws an Exception (normally a SocketTimeoutException).
     */
    private String getARecord(final String domain, final boolean useRecheckResolver) throws Exception {
        return Ipv4Utils.getResolver(useRecheckResolver).send(Message.newQuery(Record.newRecord(Ipv4Utils.getNameFromString(query), Type.A, DClass.IN,
                Ipv4Utils.DNSJAVA_TTL_TIMEOUT))).getSectionArray(Section.ANSWER)[0].rdataToString() + "/31";
    }

}
