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

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.objects.IpInfo;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Thread for TXT-Lookups.
 *
 * @author Carsten JÃ¤ger (c.jaeger@jdevelopers.de)
 *
 */
public class TxtResolver implements Runnable {

    /**
     * Reference to the resulting IpInfo-Object.
     */
    private IpInfo ipInfo;

    /**
     * Constructor.
     *
     * @param ipInfo Reference to resulting IpInfo-Object.
     */
    public TxtResolver(final IpInfo ipInfo) {
        super();
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
            ipInfo.setRunning(false, EDnsOption.TXT);
            return;
        }
        try {
            if (ipInfo.isResolvable() && !ipInfo.isSubnet()) {
//                System.err.println("Incoming TXT request: " + ipInfo.getCorrectedQuery());
                for (Record record : Ipv4Utils.getResolver(false)
                        .send(Message.newQuery(Record.newRecord(
                                ipInfo.isDomain() ? Ipv4Utils.getNameFromString(ipInfo.getCorrectedQuery())
                                        : ReverseMap.fromAddress(ipInfo.getCorrectedQuery()), Type.TXT, DClass.IN,
                                        Ipv4Utils.DNSJAVA_TTL_TIMEOUT))).getSectionArray(Section.ANSWER)) {
                    try {
                        ipInfo.getTxtInfo().addToTxtEntryList(((TXTRecord) record).rdataToString()/*.replaceAll("^[\"]|[\"]$", "")*/);
                    } catch (ClassCastException cce) {
                        // Another type than TXT? We are not interested in it here...
                        continue;
                    }
                }
            }
        } catch (Exception ignore) {
            //e.printStackTrace();
        } finally {
            ipInfo.setRunning(false, EDnsOption.TXT);
        }

    }

}
