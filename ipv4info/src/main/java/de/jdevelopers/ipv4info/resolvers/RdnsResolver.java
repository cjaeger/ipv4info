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

import java.net.InetAddress;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.objects.IpInfo;
import de.jdevelopers.ipv4info.results.RdnsResult;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Thread for RDNS-Lookups.
 *
 * @author Carsten JÃ¤ger (c.jaeger@jdevelopers.de)
 *
 */
public class RdnsResolver implements Runnable {

    /**
     * Reference to the resulting IpInfo-Object.
     */
    private IpInfo ipInfo;

    /**
     * Constructor.
     *
     * @param ipInfo Reference to resulting IpInfo-Object.
     */
    public RdnsResolver(final IpInfo ipInfo) {
        this.ipInfo = ipInfo;
    }

    public final void run() {
        if (ipInfo == null) {
            return;
        }
        try {
            while (!ipInfo.isBasicDone()) {
                Thread.sleep(Ipv4Utils.CONST_20);
            }
        } catch (InterruptedException ie) {
            ipInfo.setRunning(false, EDnsOption.RDNS);
            return;
        }
        try {
            if (ipInfo.isResolvable() && ipInfo.getUsableAddressCount() > 0) {
                 // Increment the ThreadPool if needed...
                //Ipv4Utils.adjustThreadPoolMaximumSize(ipInfo.getUsableAddressCount() - 1);
                for (final String ip : ipInfo.getUsableAddresses()) {
                    if (ipInfo.getRdnsInfo().getRdnsResult().get(ip) != null) {
                        continue;
                    }
//                    System.err.println("Incoming RDNS request: " + ip);
                    final RdnsResult rdnsResult = new RdnsResult(ip);
                    try {
                        rdnsResult.setRdns(Ipv4Utils.removeTrailingDots(getRdnsEntry(ip)));
                    } catch (Exception ignore) {
                        // IP exists, but RDNS isn't resolvable.
                        //ignore.printStackTrace();
                    } finally {
                        ipInfo.getRdnsInfo().addToRdnsResultMap(rdnsResult);
                    }
                }
            }
        } finally {
            ipInfo.setRunning(false, EDnsOption.RDNS);
        }
    }

    /**
     * Returns the RDNS-Entry for the given IP.
     *
     * @param ip IP-Address.
     * @return RDNS-Entry for the given IP.
     * @throws Exception All kind of Exceptions.
     */
    private String getRdnsEntry(final String ip) throws Exception {
        /*
         * To resolve a DNS/RDNS entry is the only case, where the InetAddress.getAllByName() function is sometimes faster than
         * a dnsjava query. So we try it first and only if the functions fails, a dnsjava query will be done.
         */
        final InetAddress[] addresses = InetAddress.getAllByName(ip);
        /*
         * In a case of error the resolved entry equals the queried IP. This seems to be a bug in the InetAddress.getAllByName()
         * function. But if it's resolved correctly, we can return here...
         */
        if (!addresses[addresses.length - 1].getCanonicalHostName().equals(ip)) {
            return addresses[addresses.length - 1].getCanonicalHostName();
        }
        /*
         * If we are here, the InetAddress.getAllByName() function did not resolved the IP correctly,
         * so we have to start a dnsjava request and from ground up, we use the more tolerant Ipv4Utils.recheckResolver
         * to resolve the entry...
         */
        final Record[] rdnsRecords = Ipv4Utils.getResolver(true)
                .send(Message.newQuery(Record.newRecord(ReverseMap.fromAddress(ip), Type.PTR, DClass.IN, Ipv4Utils.DNSJAVA_TTL_TIMEOUT)))
                .getSectionArray(Section.ANSWER);
        return Ipv4Utils.removeTrailingDots(rdnsRecords[rdnsRecords.length - 1].rdataToString());
    }

}
