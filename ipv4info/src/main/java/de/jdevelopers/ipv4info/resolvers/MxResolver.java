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

package de.jdevelopers.ipv4info.resolvers;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.xbill.DNS.DClass;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.enums.EException;
import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.objects.IpInfo;
import de.jdevelopers.ipv4info.results.MxResult;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

/**
 * Thread for MX-Lookups.
 *
 * @author Carsten Jäger
 *
 */
public class MxResolver implements Runnable {

    /**
     * Pattern to detect possible blackhole MX server.
     */
    private static final Pattern BLACKHOLE_PATTERN = Pattern.compile("blackhole\\.", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);

    /**
     * Pattern of invalid IP's in a MX response.
     */
    private static final Pattern INVALID_IP_PATTERN = Pattern.compile("^(?:(?:0\\.){3}|127\\.0\\.0\\.)(?:[\\d]+)");

    /**
     * Pattern for refused connections.
     */
    private static final Pattern REFUSED_PATTERN = Pattern.compile("refused.*?connect", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);

    /**
     * Reference to the resulting IpInfo-Object.
     */
    private IpInfo ipInfo;

    /**
     * Is this a MX retry?
     */
    private boolean isRetry;

    /**
     * To avoid redundant verfications in this thread, we cache already verifyed Domain/IP's.
     */
    private Map<String, Boolean> verifiedMap;

    /**
     * Skip unreachable entries?
     */
    private boolean skipUnreachable;

    /**
     * Skip blackhole entries?
     */
    private boolean skipBlackhole;

    /**
     * Skip disabled entries?
     */
    private boolean skipDisabled;

    /**
     * Skip pitfall entries?
     */
    private boolean skipPitfall;

    /**
     * Check root entries on error?
     */
    private boolean checkRoot;


    /**
     * Constructor.
     *
     * @param ipInfo Reference to resulting IpInfo-Object.
     * @param isRetry {@code true}, if this is a retry because of an previous error, otherwise {@code false}.
     */
    public MxResolver(final IpInfo ipInfo, final boolean isRetry) {
        this.ipInfo = ipInfo;
        this.isRetry = isRetry;
        if (this.isRetry) {
            ipInfo.setRetryResolve(false);
        }
        if (ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_DOMAIN)
                || ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_IPS)) {
            verifiedMap = new HashMap<String, Boolean>();
        }
        skipUnreachable = ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.SKIP_UNREACHABLE);
        skipBlackhole = ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.SKIP_BLACKHOLES);
        skipDisabled = ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.SKIP_DISABLED);
        skipPitfall = ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.SKIP_PITFALLS);
        checkRoot = ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.CHECK_ROOT);
    }

    public final void run() {
        if (ipInfo == null) {
            ipInfo.setRunning(false, EDnsOption.MX);
            ipInfo.setMxDone(true);
            return;
        }
        if (ipInfo.isRunning(EDnsOption.MX)) {
            return;
        }
        ipInfo.setRunning(true, EDnsOption.MX);
        ipInfo.setMxDone(false);
        try {
            while (!ipInfo.isBasicDone()) {
                Thread.sleep(Ipv4Utils.CONST_20);
            }
        } catch (InterruptedException ie) {
            ipInfo.setRunning(false, EDnsOption.MX);
            ipInfo.setMxDone(true);
            return;
        }
        resolveMx();
    }

    /**
     * Does the MX resolve.
     *
     * We can't do the check on isResovable(), because it's possible that a domain has NO A Record, but MX Record(s)!?
     * This happens mostly on misconfigured servers where the "www" subdomain is registered as the A record but
     * it might have MX entries.
     */
    private void resolveMx() {
//        System.err.println("Incoming MX " + (isRetry ? "RETRY " : "") + "request: " + ipInfo.getCorrectedQuery());
        if (ipInfo.isDomain() || ipInfo.isIp()) {
            MxResult mxResult;
            try {
                final long startMx = System.currentTimeMillis();
                final Message response = Ipv4Utils.getResolver(isRetry).send(Message.newQuery(Record.newRecord(Ipv4Utils.getNameFromString(
                        ipInfo.getCorrectedQuery()), Type.MX, DClass.IN, Ipv4Utils.DNSJAVA_TTL_TIMEOUT)));
//                System.err.println(response);
                final String additionalData = response.sectionToString(Section.ADDITIONAL);
                for (final Record record : response.getSectionArray(Section.ANSWER)) {
                    final MXRecord mxRecord;
                    try {
                        mxRecord = (MXRecord) record;
                    } catch (ClassCastException cce) {
                        // Another type than MX? We are not interested in it here...
                        continue;
                    }
                    // If the found domain doesn't fulfills the specification for a domain name or a valid IP-Address,
                    // the answer isn't correct. We can skip this record.
                    final String domain = Ipv4Utils.removeTrailingDots(mxRecord.getTarget().toString());
                    if (!Ipv4Utils.DOMAIN_PATTERN.matcher(domain).find() && !Ipv4Utils.SIMPLE_IPS_PATTERN.matcher(domain).find()
                            || INVALID_IP_PATTERN.matcher(domain).find()) {
//                        System.err.println("Invalid answer for (" + ipInfo.getCorrectedQuery() + "): " + domain);
                        continue;
                    }
                    mxResult = new MxResult(domain, mxRecord.getPriority(), mxRecord.getTTL(), ipInfo.getIpInfoOptions());
                    mxResult.setRequestStart(startMx);
                    // If skipping on domains marked as pitfall, we skip this entry.
                    if (mxResult.isPitfall() && skipPitfall) {
                        continue;
                    }
                    // If skipping on domains marked as disabled, we skip this entry.
                    if (mxResult.isDisabled() && skipDisabled && !mxResult.isPitfall()) {
                        continue;
                    }
                    if (BLACKHOLE_PATTERN.matcher(domain).find()) {
                        // If skipping on blackhole suspects is enabled, we skip this entry.
                        if (skipBlackhole) {
                            continue;
                        }
                        mxResult.setBlackholeSuspect(true);
                    }
                    // If verification of MX domains or IP's is enabled we have to verify the domain...
                    if ((ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_DOMAIN)
                            || ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_IPS)) && !mxResult.isBlackholeSuspect()
                            && !mxResult.isPitfall() && !mxResult.isDisabled()) {
                        if (!ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_DOMAIN)) {
                            ipInfo.getIpInfoOptions().getMxOptionList().add(EMxOption.VERIFY_DOMAIN);
                        }
                        mxResult.setDomainReachable(isServerUsable(mxResult.getDomain(), mxResult.getSmtpPort()));
                        if (!mxResult.isDomainReachable() && skipUnreachable) {
                            continue;
                        }
                    }
                    // If we've found something in Section.ADDITIONAL, these are normally the resolved IP's for the MX domains.
                    // So we haven't to do anymore DNS queries, to resolve the hostnames to it's IP's!
                    if (ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.RESOLVE_IPS)
                            || ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_IPS)) {
                        try {
                            if (!mxResult.isPitfall() && !mxResult.isDisabled()) {
                                if (ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_IPS)
                                        && !ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.RESOLVE_IPS)) {
                                    ipInfo.getIpInfoOptions().getMxOptionList().add(EMxOption.RESOLVE_IPS);
                                }
                                if (additionalData != null && additionalData.length() > 0) {
                                    mxResult.addToMxIps(getMxIpsFromSectionData(additionalData, mxResult));
                                    if (!mxResult.hasMxIps()) {
                                        // No valid IP's in Section.ADDITIONAL found? Then we have to to a DNS request...
                                        mxResult.addToMxIps(getMxIpsFromSectionData(Ipv4Utils.getResolver(isRetry)
                                                .send(Message.newQuery(Record.newRecord(Ipv4Utils.getNameFromString(mxResult.getDomain()), Type.A, DClass.IN,
                                                        Ipv4Utils.DNSJAVA_TTL_TIMEOUT))).sectionToString(Section.ANSWER), mxResult));
                                    }
                                } else {
                                    // No additional data found? Then we have to do a DNS request...
                                    mxResult.addToMxIps(getMxIpsFromSectionData(Ipv4Utils.getResolver(isRetry)
                                            .send(Message.newQuery(Record.newRecord(Ipv4Utils.getNameFromString(mxResult.getDomain()), Type.A, DClass.IN,
                                                    Ipv4Utils.DNSJAVA_TTL_TIMEOUT))).sectionToString(Section.ANSWER), mxResult));
                                }
                            }
                        } catch (SocketTimeoutException se) {
                            continue;
                        }
                    }
                    mxResult.setRequestEnd(System.currentTimeMillis());
                    ipInfo.getMxInfo().addToMxResultMap(mxResult);
//                    System.err.println("Found MX " + (isRetry ? "on RETRY " : "") + "for: " + ipInfo.getCorrectedQuery() + " -> " + mxResult.getDomain());
                }
                // If the NOT RECOMMENDED option CHECK_ROOT was set, we have to check the root entry.
                if (checkRoot && ipInfo.isResolvable() && ipInfo.getMxInfo().getMxResult().isEmpty()) {
                    mxResult = new MxResult(ipInfo.getCorrectedQuery(), 0, TimeUnit.HOURS.toSeconds(Ipv4Utils.CONST_20 + Ipv4Utils.CONST_4),
                            ipInfo.getIpInfoOptions());
//                    System.err.println("Doing MX ROOT check for: " + ipInfo.getCorrectedQuery());
                    mxResult.setRequestStart(System.currentTimeMillis());
                    if (isServerUsable(ipInfo.getCorrectedQuery(), Ipv4Utils.SMTP_PORT)) {
                        mxResult.setRequestEnd(System.currentTimeMillis());
                        mxResult.setDomainReachable(true);
                        ipInfo.getMxInfo().addToMxResultMap(mxResult);
                    } else {
                        mxResult = null;
                    }
                }
                ipInfo.getMxInfo().setRequestException(EException.NONE);
                if (ipInfo.getMxInfo().getMxResult().isEmpty()) {
//                    System.err.println("No MX entry found " + (isRetry ? "on RETRY " : "") + "for: " + ipInfo.getCorrectedQuery());
                }
            } catch (SocketTimeoutException ste) {
                // The domain might be valid, but we got no answer this time. So we can't say definitvely that it's invalid.
                // If this is not already a resolve retry, we assign it.
//                System.err.println("SocketTimeoutException (" + isRetry + "): " + ipInfo.getCorrectedQuery());
//                System.err.println("Setting setRetryResolve for " + ipInfo.getCorrectedQuery() + " to: " + (!ipInfo.isRetryResolve() && !isRetry));
                ipInfo.getMxInfo().setRequestException(EException.SOCKET_TIMEOUT);
                ipInfo.setRetryResolve((!ipInfo.isRetryResolve() && !isRetry));
            } catch (PortUnreachableException pue) {
                /*
                 *  No DNS-Server available at all. System's nameserver broken?
                 *  If we havent't already switched to just use the Google resolvers, we switch to them now and recall this function.
                 */
                if (!Ipv4Utils.isJustUsingGoogleResolvers()) {
                    Ipv4Utils.justUseGoogleResolvers();
                    resolveMx();
                }
            } catch (IOException ioe) {
                //System error. Mostly "Too many open files". We handle it like a SocketTimeout.
//                System.err.println("IOException (" + isRetry + "): " + ipInfo.getCorrectedQuery());
//                System.err.println("Setting isRetryResolve for " + ipInfo.getCorrectedQuery() + " to: " + (ipInfo.isRetryResolve() && !isRetry));
                ipInfo.getMxInfo().setRequestException(EException.IO_EXCEPTION);
                ipInfo.setRetryResolve((!ipInfo.isRetryResolve() && !isRetry));
            } catch (Throwable t) {
                t.printStackTrace();
            } finally {
                if (verifiedMap != null) {
                    verifiedMap.clear();
                }
            }
        }
        ipInfo.setRunning(false, EDnsOption.MX);
        ipInfo.setMxDone(true);
    }

    /**
     * Checks a given Domain/IP can be connected to.
     *
     * @param server Domain/IP.
     * @param port Port.
     * @return {@code TRUE} if the connection was successfull, otherwise {@code FALSE}.
     */
    private boolean isServerUsable(final String server, final int port) {
        if (server == null || server.length() < Ipv4Utils.CONST_4) {
            return false;
        }
        Socket so = null;
        try {
            so = new Socket();
            so.setSoTimeout((int) TimeUnit.SECONDS.toMillis(Ipv4Utils.CONST_3));
            so.connect(new InetSocketAddress(server, port), (int) TimeUnit.SECONDS.toMillis(Ipv4Utils.CONST_2));
            return so.isConnected();
        } catch (ConnectException ce) {
            /*
             *  If the exception message contains "refused", the server is alive, but won't talk to me right now.
             *  As the server is theoratically usable, the result depends on the EMxOption.SKIP_REFUSED option...
             */
            if (REFUSED_PATTERN.matcher(ce.getMessage()).find()) {
                return !ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.SKIP_REFUSED);
            }
        } catch (SocketTimeoutException ste) {
            // Server not reachable in the given timeout of 2 sec. for connect and 3 sec. for a response,
            // so we declare it as unusable..
        } catch (UnknownHostException uhe) {
            // Server doesn't exist, so it's unusable..
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            try {
              if (so != null) {
                  so.close();
              }
            } catch (Exception ignore) {
            }
        }
        return false;
    }

    /**
     * Returns a set of IP's for the given MX domain.
     *
     * @param sectionData String to search for IP's.
     * @param mxResult MxResult-Object.
     * @return Set of IP's for the given MX domain.
     */
    private Map<String, Boolean> getMxIpsFromSectionData(final String sectionData, final MxResult mxResult) {
//        System.err.println("sectionData: " + sectionData);
        final Matcher matcher = Pattern.compile(String.format(Ipv4Utils.VARIABLE_MX_DOMAIN_IPS, mxResult.getDomain())).matcher(sectionData);
        if (matcher.find()) {
            matcher.reset();
            final Map<String, Boolean> result = new TreeMap<String, Boolean>();
            while (matcher.find()) {
                if (!ipInfo.getIpInfoOptions().getMxOptionList().contains(EMxOption.VERIFY_IPS)) {
                    result.put(matcher.group(1), false);
                } else {
                    if (mxResult.isBlackholeSuspect()) {
                        // Don't check entries under blackhole suspicion
                        verifiedMap.put(matcher.group(1), false);
                    } else {
                        final Boolean verified = verifiedMap.get(matcher.group(1));
                        if (verified == null) {
                            verifiedMap.put(matcher.group(1), isServerUsable(matcher.group(1), mxResult.getSmtpPort()));
                        }
                    }
                    if (!verifiedMap.get(matcher.group(1)) && (skipUnreachable || skipBlackhole)) {
                        continue;
                    }
                    result.put(matcher.group(1), verifiedMap.get(matcher.group(1)));
                }
            }
            return result;
        }
        return null;
    }

}
