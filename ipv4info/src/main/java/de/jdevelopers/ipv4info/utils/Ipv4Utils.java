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

package de.jdevelopers.ipv4info.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.WeakHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;

import de.jdevelopers.ipv4info.enums.EDnsOption;
import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.objects.IpInfo;

/**
 * Utility class for the Ipv4Info package.
 *
 * @author Carsten Jäger
 *
 */
public final class Ipv4Utils {

    /**
     * Divider for dividing results in the toString() Method.
     */
    public static final transient String DIVIDER = "-----------------------------------------------------------------------------------------------------\n";

    /**
     * Basic RegEx-String for IP-Addresses.
     */
    public static final String IP_ADDRESS = "^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
            + "\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";

    /**
     * Domain-Pattern.
     */
    public static final Pattern DOMAIN_PATTERN = Pattern.compile("^((?:[a-z0-9]+(?:-[a-z0-9]+)*\\.)+[a-z]{2,})", Pattern.CASE_INSENSITIVE
            | Pattern.UNICODE_CASE);

    /**
     * Top-Level-Domain-Pattern.
     */
    public static final Pattern TLD_PATTERN = Pattern.compile("(?:[^.]+[.]){0,1}([^.]+[.]([^.]+))$", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);

    /**
     * IP-Address-Pattern.
     */
    public static final Pattern ADDRESS_PATTERN = Pattern.compile(IP_ADDRESS + "$");

    /**
     * CIDR-Pattern.
     */
    public static final Pattern CIDR_PATTERN = Pattern.compile(IP_ADDRESS + "/(\\d{1,2})$");

    /**
     * Simple IP-Address/Subnet pattern that just checks for the presence of the four octets.
     */
    public static final Pattern SIMPLE_IPS_PATTERN = Pattern.compile("((?:[0-9]{1,3}\\.){3}[0-9]{1,3})(?:/([\\d]+))*$");

    /**
     * Pattern to get MX hostname and it's priority.
     */
    public static final Pattern MX_PRIO_PATTERN = Pattern.compile("^([\\d]*)\\s*(.*?)\\.$");

    /**
     * String for findings IP's in an DNS-Additional-Section answer. %s will be replaced by the actual MX domain.
     */
    public static final String VARIABLE_MX_DOMAIN_IPS = "(?m)\\Q%s\\E.*?\\bIN\\b.*?\\bA\\b.*?(" + SIMPLE_IPS_PATTERN + ")";

    /**
     * Constant 2.
     */
    public static final byte CONST_2 = 2;

    /**
     * Constant 3.
     */
    public static final byte CONST_3 = 3;

    /**
     * Constant 4.
     */
    public static final byte CONST_4 = 4;

    /**
     * Constant 5.
     */
    public static final byte CONST_5 = 5;

    /**
     * Constant 8.
     */
    public static final byte CONST_8 = 8;

    /**
     * Constant 10.
     */
    public static final byte CONST_10 = 10;

    /**
     * Constant 20.
     */
    public static final byte CONST_20 = 20;

    /**
     * Constant 30.
     */
    public static final byte CONST_30 = 30;

    /**
     * Constant 60.
     */
    public static final byte CONST_60 = 60;

    /**
     * Constant 100.
     */
    public static final byte CONST_100 = 100;

    /**
     * Constant 255.
     */
    public static final short CONST_255 = 255;

    /**
     * Timeout for establishing URL connections. Standard: 2 sec.
     */
    public static final int URL_CONNECT_TIMEOUT = (int) TimeUnit.MINUTES.toMillis(CONST_2);

    /**
     * Timeout for read operations from URL connections. Standard: 4 sec.
     */
    public static final int URL_READ_TIMEOUT = (int) TimeUnit.MINUTES.toMillis(CONST_4);

    /**
     * Time to hold dnsjava request results.
     */
    public static final int DNSJAVA_TTL_TIMEOUT = Ipv4Utils.CONST_60 * Ipv4Utils.CONST_60;

    /**
     * Map that stores the results of DNS-Queries for further queries.
     */
    public static final Map<String, IpInfo> RESULT_POOL = new WeakHashMap<String, IpInfo>();

    /**
     * Default port for SMTP connections.
     */
    public static final byte SMTP_PORT = 25;

    /**
     * Default timeout for socket connections (3 sec).
     */
    public static final int DEFAULT_SOCKET_TIMEOUT = 3000;

    /**
     * Replace string to auto correct faulty incoming query strings.
     */
    private static final String QUERY_CORRECTION = "(?i)^(?:https?|ftps?|udp|tcp)://|.*?[@]+.*?[.]*|^[.]+|[.]{2,}";

    /**
     * Map to store prefixes for querying WHOIS-Servers.
     */
    private static final Map<String, String> WHOIS_QUERY_PREFIX_MAP = new HashMap<String, String>();

    /**
     * Addresses of the Google Nameservers.
     */
    private static final String[] GOOGLE_DNS_IPS = new String[] {"8.8.8.8", "8.8.4.4"};

    /**
     * Is the Apache Commons Lang 3.x package available in classpath?
     */
    private static boolean apacheCommonsLangAvailable = true;

    /**
     * Is the dnsjava 2.1.x package available in classpath?
     */
    private static boolean dnsjavaAvailable = true;

    /**
     * Maximum lifetime of cached objects in RESULT_POOL and WHOIS_SERVER_CACHE (default: 1800000 msec. / 30 min).
     */
    private static long internalCacheTTL = TimeUnit.MINUTES.toMillis(CONST_30);

    /**
     * Maximum number of allowed threads in the ThreadPool (default: 20).
     */
    private static int maximumPoolSize = CONST_2 * CONST_10;

    /**
     * Shall the maximumPoolSize of the ThreadPool be autoadjusted depending on the number of queries to resolve? (default: true).
     */
    private static boolean autoAdjustThreadPoolSize = true;

    /**
     * Global ThreadPool.
     */
    private static ThreadPoolExecutor threadPool = createBoundedCachedThreadPool(0, maximumPoolSize, CONST_60, TimeUnit.SECONDS);

    /**
     * Global small ThreadPool used for rechecks.
     */
    private static ThreadPoolExecutor recheckThreadPool;

    /**
     * ExtendedResolver for dnsjava queries.
     */
    private static ExtendedResolver resolver;

    /**
     * ExtendedResolver for dnsjava queries with MX recheck settings.
     */
    private static ExtendedResolver recheckResolver;

    /**
     * Additional Google-Resolvers.
     */
    private static List<Resolver> googleResolverList;

    /**
     * Are we just only using the Google resolvers?
     */
    private static boolean justUsingGoogleResolvers;

    /**
     * Timer that schedules the CacheObserver-TimerTask.
     */
    private static Timer cacheTimer;

    /**
     * Document that holds the internal configuration XML file.
     */
    private static Document document;

    // Initialization block.
    static {

        // Enables dnsjava messages...
//        System.setProperty("dnsjava.options", "verbose,verbosecache");
        
        // Check dependecies
        // 1. dnsjava
        try {
            Class.forName("org.xbill.DNS.Record");
        } catch (ClassNotFoundException cnfe) {
            dnsjavaAvailable = false;
            System.err.println("\nFATAL ERROR: The dnsjava 2.1.x package could not be found in your classpath.");
            System.err.println("You MUST include this package, because all DNS requests depends on this package. NOTHING WORKS without it!");
            System.err.println("Download package at: http://sourceforge.net/projects/dnsjava/");
        }

        // Init essential variables. Some other will just be initialized on demand.
        
        // Set the internal cache ttl for successful name lookups from the name service to the same value as DNSJAVA_TTL_TIMEOUT.
        //System.setProperty("networkaddress.cache.ttl", String.valueOf(DNSJAVA_TTL_TIMEOUT));
        // Known prefixes for querying WHOIS servers (to be extended ?!)
        WHOIS_QUERY_PREFIX_MAP.put("de", "-T dn,ace ");
        // Creates an dnsjava ExtendedResolver with the system default DNS-Server(s).
        try {
            resolver = new ExtendedResolver();
        } catch (UnknownHostException uhe) {
            // Can only occur, if there is no system nameserver, or nameserver(s) are out of service.
            // So we switch to use just the Google resolvers...
            try {
                resolver = new ExtendedResolver(GOOGLE_DNS_IPS);
            } catch (UnknownHostException uhe2) {
                uhe2.printStackTrace();
            }
        }
        if (resolver != null) {
            resolver.setTimeout(CONST_3);
            resolver.setRetries(0);
        }
    }

    /**
     * Constructor.
     *
     * As this class just contains static functions, the access level of the constructor is private to avoid any instantiation!
     */
    private Ipv4Utils() {
    }

    /**
     * Creates a ThreadPool for running requests threads.
     *
     * This procedure combines the very fast possibility of adding new threads to the ThreadPool which can be done by using
     * a fixed ThreadPool (Executors.nexFixedThreadPool()) with the advantage of a cached ThreadPool (Executors.newCachedThreadPool())
     * to remove no longer used (idle) threads from the pool which reduces the usage of system resources.
     *
     * Setting the corePoolSize to 0 prevents the ThreadPoool to use any system resources when there is nothing to do
     * and will automatically shut down the ThreadPool after the keepAliveTime. So this can make the call to shutDownThreadPool()
     * obsolete (but this is NOT recommended!).
     *
     * @param corePoolSize The core number of threads.
     * @param maximumPoolSize The maximum allowed number of threads.
     * @param keepAliveTime The time limit for which threads may remain idle before they being terminated.
     * @param timeUnit The time unit of the keepAliveTime argument.
     * @return ThreadPoolExecutor.
     */
    private static ThreadPoolExecutor createBoundedCachedThreadPool(final int corePoolSize, final int maximumPoolSize, final long keepAliveTime,
            final TimeUnit timeUnit) {
        @SuppressWarnings("serial")
        final LinkedBlockingQueue<Runnable> queue = new LinkedBlockingQueue<Runnable>() {
            public boolean offer(final Runnable r) {
                if (size() > 1) {
                    return false;
                }
                return super.offer(r);
            };
            public boolean add(final Runnable r) {
                if (super.offer(r)) {
                    return true;
                } else {
                    throw new IllegalStateException();
                }
            }
        };
        RejectedExecutionHandler handler = new RejectedExecutionHandler() {
            public void rejectedExecution(final Runnable r, final ThreadPoolExecutor executor) {
                queue.add(r);
            }
        };
        return new ThreadPoolExecutor(corePoolSize, maximumPoolSize, keepAliveTime, timeUnit, queue, handler);
    }

    /**
     * Sets the params of the global ThreadPool.
     *
     * @param corePoolSize Core pool size (min. 0, max. 200).
     * @param maximumPoolSize Maximum pool size (min. 1, max. 200).
     * @param keepAliveTime Maximum allowed idle time of ThreadPool threads (min. 0, max. 24h).
     * @param timeUnit TimeUnit as how the keepAliveTime parameter shall be interpreted.
     * @return {@code true}, if the params was set correctly, otherwise {@code false}.
     */
    public static boolean setThreadPoolParams(final int corePoolSize, final int maximumPoolSize, final long keepAliveTime,
            final TimeUnit timeUnit) {
        // Checking parameter integrity
        if (corePoolSize < 0 || corePoolSize > CONST_2 * CONST_100 || corePoolSize > maximumPoolSize) {
            System.err.println("Invalid corePoolSize given.");
            return false;
        }
        if (maximumPoolSize < 1 || maximumPoolSize > CONST_2 * CONST_100) {
            System.err.println("Invalid maximumPoolSize given.");
            return false;
        }
        if (timeUnit == null || keepAliveTime < 0 || timeUnit.toSeconds(keepAliveTime) > (CONST_60 * CONST_60) * (CONST_4 + CONST_20)) {
            System.err.println("Invalid keepAliveTime or TimeUnit given.");
            return false;
        }
        Ipv4Utils.maximumPoolSize = maximumPoolSize;
        if (threadPool.getCorePoolSize() != corePoolSize) {
            System.err.println("Setting threadPool's corePoolSize to: " + corePoolSize);
            threadPool.setCorePoolSize(corePoolSize);
        }
        if (threadPool.getMaximumPoolSize() != maximumPoolSize) {
            System.err.println("Setting threadPool's maximumPoolSize to: " + maximumPoolSize);
            threadPool.setMaximumPoolSize(maximumPoolSize);
        }
        if (threadPool.getKeepAliveTime(timeUnit) != keepAliveTime) {
            System.err.println("Setting threadPool's keepAliveTime to: " + keepAliveTime + " " + timeUnit);
            threadPool.setKeepAliveTime(keepAliveTime, timeUnit);
        }
        return true;
    }

    /**
     * Convenience method to adjust just the maximum pool size value of the ThreadPool.
     *
     * @param maximumPoolSize Maximum pool size (min. 1, max. 200).
     */
    public static void setThreadPoolMaximumPoolSize(final int maximumPoolSize) {
        setThreadPoolParams(threadPool.getCorePoolSize(), maximumPoolSize, threadPool.getKeepAliveTime(TimeUnit.SECONDS), TimeUnit.SECONDS);
    }

    /**
     * Convenience method to adjust just the keepAliveTime of the ThreadPool threads.
     *
     * @param keepAliveTime Maximum allowed idle time of ThreadPool threads (min. 0, max. 24h).
     * @param timeUnit TimeUnit as how the keepAliveTime parameter shall be interpreted.
     */
    public static void setThreadPoolKeepAliveTime(final long keepAliveTime, final TimeUnit timeUnit) {
        setThreadPoolParams(threadPool.getCorePoolSize(), threadPool.getMaximumPoolSize(), keepAliveTime, timeUnit);
    }

    /**
     * Returns the value of autoAdjustThreadPoolMaximumSize.
     *
     * @return The value of autoAdjustThreadPoolMaximumSize.
     */
    public static boolean isAutoAdjustThreadPoolMaximumSize() {
        return autoAdjustThreadPoolSize;
    }

    /**
     * Sets the value of autoAdjustThreadPoolMaximumSize.
     *
     * @param autoAdjustThreadPoolSize The value of autoAdjustThreadPoolMaximumSize.
     */
    public static void setAutoAdjustThreadPoolSize(final boolean autoAdjustThreadPoolSize) {
        Ipv4Utils.autoAdjustThreadPoolSize = autoAdjustThreadPoolSize;
        if (!autoAdjustThreadPoolSize) {
            // Reset set maximumPoolSize value to the default.
            threadPool.setMaximumPoolSize(Ipv4Utils.maximumPoolSize);
        }
    }

    /**
     * Retruns the number of the actual free slots in the ThreadPool.
     *
     * @return Number of the actual free slots in the ThreadPool.
     */
    public static int getThreadPoolFreeSlots() {
        return threadPool.getMaximumPoolSize() - threadPool.getPoolSize();
    }

    /**
     * Increments the maximumPoolSize value of the ThreadPool according to the number of incoming queries.
     *
     * This function is just for internal use and is only called by the getUnresolvedRequestsFromResultPool() function
     * which is only executed, if a resolveing option was set AFTER adding queries!
     *
     * The automatic incrementation just takes place, if the pool is actually full and the value of maximumPoolSize is
     * beyond 100 threads. The maximum incrementation will be 25% of the actual value of threadPool.getMaximumPoolSize().
     *
     * @param numberOfQueries Number of incoming queries.
     */
    public static void autoAdjustThreadPoolMaximumSize(final int numberOfQueries) {
//        System.err.println("numberOfQueries: " + numberOfQueries);
//        System.err.println("getPoolSize: " + threadPool.getPoolSize());
//        System.err.println("getMaximumPoolSize: " + threadPool.getMaximumPoolSize());
        /*
         * A correction of the maximumPoolSize just makes sense, if the pool is actually full.
         * So, if there are enough free slots available, there is not need to increment the pool size and we do nothing...
         */
        if (numberOfQueries <= 0 || threadPool.getMaximumPoolSize() >= CONST_100
                || (getThreadPoolFreeSlots() >= numberOfQueries)) {
            return;
        }
        int maximumPoolSize = threadPool.getMaximumPoolSize();
        // If all slots are full and the actual pool size is less than 50 threads, we set a value of 50 threads.
        if (threadPool.getPoolSize() == threadPool.getMaximumPoolSize()) {
            // If there are more than 50 queries waiting, we set the size to 50 threads first.
            if (numberOfQueries - threadPool.getMaximumPoolSize() > CONST_5 * CONST_10 && threadPool.getMaximumPoolSize() < CONST_5 * CONST_10) {
                maximumPoolSize = CONST_5 * CONST_10;
            } else {
                maximumPoolSize += numberOfQueries - threadPool.getMaximumPoolSize();
                if (maximumPoolSize > CONST_5 * CONST_10) {
                    maximumPoolSize = CONST_5 * CONST_10;
                }
            }
        }
        if (maximumPoolSize < numberOfQueries) {
            // Add additional 25% of the actual maximumPoolSize value.
            maximumPoolSize += (numberOfQueries - threadPool.getMaximumPoolSize()) / CONST_4;
            if (maximumPoolSize > numberOfQueries) {
                maximumPoolSize = numberOfQueries;
            }
        }
        if (threadPool.getMaximumPoolSize() < maximumPoolSize) {
            if (maximumPoolSize < CONST_100) {
                threadPool.setMaximumPoolSize(maximumPoolSize);
            } else {
                threadPool.setMaximumPoolSize(CONST_100);
            }
            System.err.println("Auto adjusted maximumPoolSize value to: " + threadPool.getMaximumPoolSize());
        }
    }

    /**
     * Returns the ThreadPool.
     *
     * @return The ThreadPool
     */
    public static ThreadPoolExecutor getThreadPool() {
        return threadPool;
    }

    /**
     * Returns the MX recheck ThreadPool.
     * This ThreadPool is NOT configurable!
     *
     * @return The MX recheck ThreadPool
     */
    public static synchronized ExecutorService getRecheckThreadPool() {
        if (recheckThreadPool == null) {
//            System.err.println("#### CREATING recheckThreadPool");
            recheckThreadPool = createBoundedCachedThreadPool(0, CONST_10, CONST_60, TimeUnit.SECONDS);
        }
        return recheckThreadPool;
    }

    /**
     * Immediately shuts down the ThreadPool.
     */
    public static void shutDownThreadPool() {
        shutDownThreadPool(0, TimeUnit.SECONDS);
    }

    /**
     * Shuts down the ThreadPool and waits for shutdown.
     *
     * @param timeout Timeout for shutdown.
     * @param timeUnit The TimeUnit as how the timeout parameter shall be interpreted.
     */
    public static void shutDownThreadPool(final int timeout, final TimeUnit timeUnit) {
        enableCacheObserver(false);
        if (recheckThreadPool != null && !recheckThreadPool.isShutdown()) {
            recheckThreadPool.shutdown();
        }
        if (!threadPool.isShutdown()) {
            threadPool.shutdown();
            if (timeout <= 0) {
                return;
            }
        }
        try {
            recheckThreadPool.awaitTermination(timeout, timeUnit);
        } catch (Exception ignore) {
        }
        try {
            threadPool.awaitTermination(timeout, timeUnit);
        } catch (InterruptedException ignore) {
        }
    }

    /**
     * Returns the value of dnsjavaAvailable.
     *
     * @return The value of dnsjavaAvailable.
     */
    public static boolean isDnsjavaAvailable() {
        return dnsjavaAvailable;
    }

    /**
     * Returns the value of apacheCommonsLangAvailable.
     *
     * @return The value of apacheCommonsLangAvailable.
     */
    public static boolean isApacheCommonsLangAvailable() {
        return apacheCommonsLangAvailable;
    }

    /**
     * Returns the value of internalCacheTTL.
     *
     * @param timeUnit The TimeUnit as how the internalCacheTTL value shall be returned.
     * @return The value of internalCacheTTL.
     */
    public static long getInternalCacheTTL(final TimeUnit timeUnit) {
        return timeUnit.convert(internalCacheTTL, TimeUnit.MILLISECONDS);
    }

    /**
     * Sets the value of internalCacheTTL in the given TimeUnit.
     * The maximum value is restricted to 86400 sec. (24 hours).
     * This value will be used by the CacheRunner-Task to decide when to remove a value from RESULT_POOL.
     *
     * @param internalCacheTTL The value of internalCacheTTL.
     * @param timeUnit The TimeUnit as how the internalCacheTTL parameter shall be interpreted.
     */
    public static void setInternalCacheTTL(final int internalCacheTTL, final TimeUnit timeUnit) {
        final long givenTime = timeUnit.toMillis(internalCacheTTL);
        if (givenTime <= TimeUnit.HOURS.toMillis(CONST_4 + CONST_20)) {
            Ipv4Utils.internalCacheTTL = givenTime;
        }
    }

    /**
     * Initializes the CacheObserver-TimerTask to run every 20 min. after an initial delay of 10 min.
     */
    private static void initCacheObserver() {
        System.err.println("Enabling CacheObserver");
        cacheTimer = new Timer();
        cacheTimer.schedule(new CacheObserver(), TimeUnit.MINUTES.toMillis(CONST_10), TimeUnit.MINUTES.toMillis(CONST_20));
    }

    /**
     * Enables/Disables the CacheObserver-TimerTask.
     *
     * @param enable  {@code TRUE} to enable the CacheObserver-Task, otherwise {@code FALSE}.
     */
    public static void enableCacheObserver(final boolean enable) {
        if (enable && cacheTimer == null) {
            initCacheObserver();
        } else if (cacheTimer != null) {
            System.err.println("Disabling CacheObserver");
            cacheTimer.cancel();
            cacheTimer.purge();
            cacheTimer = null;
        }
    }

    /**
     * Returns the DNS-Resolver.
     *
     * @param useRecheckResolver Shall the Fallback-Resolver be used?
     * @return The value of resolver or fallbackResolver.
     */
    public static ExtendedResolver getResolver(final boolean useRecheckResolver) {
        if (useRecheckResolver) {
            if (recheckResolver == null) {
//                System.err.println("### New recheckResolver");
                recheckResolver = getNewResolver();
                recheckResolver.setTimeout(CONST_20);
                recheckResolver.setRetries(1);
            }
            return recheckResolver;
        }
        return resolver;
    }


    /**
     * Enables or disables the DNS-Server-Roundrobin-Usage of the resolver.
     *
     * The round robin usage will just be enabled if there is more than one nameserver available.
     *
     * @param useRoundRobin {@code true} enables Roundrobin usage, {@code false} disables it (default).
     */
    public static void setUseRoundRobin(final boolean useRoundRobin) {
        setUseRoundRobin(useRoundRobin, false);
    }

    /**
     * Enables or disables the DNS-Server-Roundrobin-Usage of the resolver.
     *
     * The round robin usage will just be enabled if there is more than one nameserver available.
     *
     * @param useRoundRobin {@code true} enables Roundrobin usage, {@code false} disables it (default).
     * @param addGoogleResolvers {@code true} to add the Google resolvers to the resolver list.
     */
    public static void setUseRoundRobin(final boolean useRoundRobin, final boolean addGoogleResolvers) {
        if (useRoundRobin) {
            if (addGoogleResolvers) {
                addGoogleResolvers(true);
            }
            resolver.setLoadBalance(resolver.getResolvers().length > 1);
        } else {
            resolver.setLoadBalance(false);
        }
    }

    /**
     * Enables or disables the usage of the additional Google-DNS-Servers.
     *
     * @param addResolvers {@code true} to use the Google DNS-Servers, otherwise {@code false}.
     */
    public static void addGoogleResolvers(final boolean addResolvers) {
        if (!addResolvers) {
            if (googleResolverList != null) {
                for (Resolver googleResolver : googleResolverList) {
                    resolver.deleteResolver(googleResolver);
                }
            }
        } else {
            if (googleResolverList == null) {
                googleResolverList = new ArrayList<Resolver>();
                for (final String address : GOOGLE_DNS_IPS) {
                    try {
                        googleResolverList.add(new SimpleResolver(address));
                    } catch (UnknownHostException ignore) {
                    }
                }
            }
            final List<Resolver> resolverList = Arrays.asList(resolver.getResolvers());
            for (Resolver r : googleResolverList) {
                if (!resolverList.contains(r)) {
                    resolver.addResolver(r);
                }
            }
        }
    }

    /**
     * Returns the value of justUsingGoogleResolvers.
     *
     * @return The value of justUsingGoogleResolvers.
     */
    public static boolean isJustUsingGoogleResolvers() {
        return justUsingGoogleResolvers;
    }

    /**
     * Disables the systems own nameservers and just uses the Google ones.
     *
     * NOTICE: The Google DNS-servers doesn't seem to resolve MX entries.
     * So if MX entries shall be resolved you shouldn't call this function!
     */
    public static void justUseGoogleResolvers() {
        if (!isJustUsingGoogleResolvers()) {
            System.err.println("Switching to JUST use the Google resolvers!");
            for (Resolver r : resolver.getResolvers()) {
                resolver.deleteResolver(r);
            }
            justUsingGoogleResolvers = true;
            addGoogleResolvers(true);
        }
    }

    /**
     * Sets the number of retries for the resolver.
     *
     * @param retries Number of retries.
     */
    public static void setResolverRetries(final int retries) {
        resolver.setRetries(retries >= 0 ? retries : 0);
    }

    /**
     * Sets the timeout for an resolver in the given TimeUnit (max: 120 sec.).
     *
     * @param timeout Timeout for the resolver in seconds.
     * @param timeUnit The TimeUnit as how the timeout parameter shall be interpreted.
     * @param useRecheckResolver Are this settings for the recheckResolver?
     */
    private static void setResolverTimeout(final int timeout, final TimeUnit timeUnit, final boolean useRecheckResolver) {
        // The value has to be between 1 and 120 seconds.
        final int givenTimeout = (int) timeUnit.convert(timeout, TimeUnit.SECONDS);
        if (givenTimeout > 0 && givenTimeout <= CONST_2 * CONST_60) {
            if (useRecheckResolver) {
                recheckResolver.setTimeout(givenTimeout);
            } else {
                resolver.setTimeout(givenTimeout);
            }
        }
    }

    /**
     * Sets the timeout for the resolver in the given TimeUnit (max: 120 sec.).
     *
     * @param timeout Timeout for the resolver in seconds.
     * @param timeUnit The TimeUnit as how the timeout parameter shall be interpreted.
     */
    public static void setResolverTimeout(final int timeout, final TimeUnit timeUnit) {
        setResolverTimeout(timeout, timeUnit, false);
    }

    /**
     * Sets the number of retries for the resolver.
     *
     * @param retries Number of retries.
     */
    public static void setRecheckResolverRetries(final int retries) {
        if (recheckResolver == null) {
            // We have to initiate the resolver first...
            getResolver(true);
        }
        if (retries > 0) {
            recheckResolver.setRetries(retries);
        } else {
            recheckResolver.setRetries(1);
        }
    }

    /**
     * Sets the timeout for the resolver in seconds.
     *
     * @param timeout Timeout for the resolver in seconds.
     * @param timeUnit The TimeUnit as how the timeout parameter shall be interpreted.
     */
    public static void setRecheckResolverTimeout(final int timeout, final TimeUnit timeUnit) {
        if (recheckResolver == null) {
            // We have to initiate the resolver first...
            getResolver(true);
        }
        setResolverTimeout(timeout, timeUnit, true);
    }

    /**
     * Returns a new ExtendedResolver with the resolvers of the standard resolver.
     * Useful for using temporary different timeout or retry settings.
     *
     * @return ExtendedResolver with the resolvers of the standard resolver.
     */
    public static ExtendedResolver getNewResolver() {
        ExtendedResolver result = null;
        try {
            result = new ExtendedResolver(resolver.getResolvers());
        } catch (UnknownHostException e) { }
        return result;
    }

    /**
     * Changes the default resolver.
     *
     * @param resolver ExtendedResolver.
     */
    public static void setNewResolver(final ExtendedResolver resolver) {
        Ipv4Utils.resolver = resolver;
    }

    /**
     * Corrects the incoming IP/Domain query by replacing incorrect leading characters.
     *
     * @param query IP or Domain.
     * @return Corrected IP/Domain.
     */
    public static String getCorrectedQuery(final String query) {
        return query == null ? null : query.replaceAll(QUERY_CORRECTION, "").toLowerCase();
    }

    /**
     * Resolve an IP-Address through a matcher result into an int value.
     *
     * @param matcher Matcher.
     * @return int value of an IP-Address.
     */
    public static int matchAddress(final Matcher matcher) {
        if (matcher == null) {
            return 0;
        }
        int result = 0;
        for (byte i = 1; i <= CONST_4; ++i) {
            result |= ((Short.parseShort(matcher.group(i)) & CONST_255) << CONST_8 * (CONST_4 - i));
        }
        return result;
    }

    /**
     * Converts an IP-Address to int.
     *
     * @param ip IP-Address.
     * @return IP-Address as int.
     */
    public static int ipToInt(final String ip) {
        if (ip == null) {
            return 0;
        }
        return matchAddress(ADDRESS_PATTERN.matcher(ip));
    }

    /**
     * Converts an int value to a 4-byte length short array.
     *
     * @param intValue int value.
     * @return short array.
     */
    public static short[] intToShortArray(final int intValue) {
        final short[] result = new short[CONST_4];
        for (byte i = CONST_4 - 1; i >= 0; --i) {
            result[i] |= ((intValue >>> CONST_8 * ((CONST_4 - 1) - i)) & (CONST_255));
        }
        return result;
    }

    /**
     * Converts an int value to a list containing short values.
     *
     * @param intValue int value.
     * @return List of short values.
     */
    public static List<Short> intToShortList(final int intValue) {
        final List<Short> result = new ArrayList<Short>();
        for (short s : intToShortArray(intValue)) {
            result.add(s);
        }
        return result;
    }

    /**
     * Formats a List with short values into it's IP-Address representation.
     *
     * @param shortList List with short values.
     * @param reverseOrder {@code TRUE} if the incoming list shall be sorted in reverse order, otherwise {@code FALSE}.
     * @return IP-Address.
     */
    public static String formatToIp(final List<Short> shortList, final boolean reverseOrder) {
        if (shortList == null) {
            return null;
        }
        if (reverseOrder) {
            Collections.reverse(shortList);
        }
        return shortList.toString().replaceAll(",[ ]*", ".").replaceAll("[\\[\\]]", "");
    }

    /**
     * Revereses an IP-Address.
     *
     * @param ip IP-Address.
     * @return Reversed IP-Address.
     */
    public static String reverseIp(final String ip) {
        if (ip == null || ip.length() == 0) {
            return null;
        }
        final List<Short> shortList = new ArrayList<Short>();
        try {
            for (String s : ip.split("[.]")) {
                shortList.add(Short.parseShort(s));
            }
            return formatToIp(shortList, true);
        } catch (Exception ignore) {
            //
        } finally {
            shortList.clear();
        }
        return null;
    }

    /**
     * Converts an IP-Address and the given netmask into an IP-Address in CIDR-Notation (xxx.xxx.xxx.xxx/yy).
     *
     * @param ip IP-Address.
     * @param mask Netmask.
     * @return IP-Address in CIDR-Notation.
     */
    public static String toCidrAddress(final String ip, final String mask) {
        if (ip == null || mask == null) {
            return null;
        }
        return ip + "/" + countBits(ipToInt(mask));
    }

    /**
     * Counts the number of 1-Bits in a 32-bit int value and uses a "divide-and-conquer" strategy. (see Hacker's
     * Delight, Section 5.1).
     *
     * @param intValue int value.
     * @return Number of 1-Bits.
     */
    public static int countBits(final int intValue) {
        final byte const16 = 16;
        final byte const3F = 0x0000003F;
        final int const33 = 0x33333333;
        final int const55 = 0x55555555;
        final int const0F = 0x0F0F0F0F;
        int result = intValue;
        result -= ((result >>> 1) & const55);
        result = (result & const33) + ((result >>> 2) & const33);
        result = (result + (result >>> CONST_4)) & const0F;
        result += (result >>> CONST_8);
        result += (result >>> const16);
        return result & const3F;
    }

    /**
     * Returns the incoming string without trailing dots.
     *
     * @param string Incoming string.
     * @return Incoming string without trailing dots or {@code NULL} if incoming was {@code NULL}.
     */
    public static String removeTrailingDots(final String string) {
        if (string == null) {
            return null;
        }
        return string.replaceFirst("[.]+$", "");
    }

    /**
     * Tests a query if it's a hostname.
     *
     * @param query Incoming Query.
     * @return Returns {@code TRUE} if the query is a hostname, otherwise it returns {@code FALSE}.
     */
    public static boolean queryIsHostname(final String query) {
        if (query == null || query.length() == 0) {
            return false;
        }
        return DOMAIN_PATTERN.matcher(query).find();
    }

    /**
     * Tests a query if it's a CIDR-Notation (subnet).
     *
     * @param query Incoming Query.
     * @return Returns {@code TRUE} if the query is a CIDR-Notation (subnet), otherwise it returns {@code FALSE}.
     */
    public static boolean queryIsSubnet(final String query) {
        if (query == null || query.length() == 0) {
            return false;
        }
        return CIDR_PATTERN.matcher(query).find();
    }

    /**
     * Constructs a dnsjava Name-Object from a string.
     *
     * @param s String.
     * @return dnsjava Name-Object.
     * @throws TextParseException TextParseException
     */
    public static Name getNameFromString(final String s) throws TextParseException {
        if (s == null) {
            return new Name(".");
        }
        return new Name(s + ".");
    }

    /**
     * Returns all unresolved or unsufficient results from the result pool and re-adds them to the queries.
     *
     * @param dnsRequest Type of the DNS request.
     * @param optionsList List of request options.
     * @return List of IpInfo objects to be rechecked.
     */
    @SuppressWarnings("unchecked")
    public static List<IpInfo> getUnresolvedRequestsFromResultPool(final EDnsOption dnsRequest, final List<?> optionsList) {
        final List<IpInfo> result = new ArrayList<IpInfo>();
        for (IpInfo ipInfo : RESULT_POOL.values()) {
                switch (dnsRequest) {
                case MX:
                    if (!ipInfo.isRunning(EDnsOption.MX) && (!ipInfo.getIpInfoOptions().isResolveMx() || !ipInfo.getIpInfoOptions().getMxOptionList()
                            .equals((List<EMxOption>) optionsList))) {
//                        System.err.println("MX: getUnresolvedRequestsFromResultPool: " + ipInfo.getCorrectedQuery());
//                        System.err.println("MX options: " + (List<EMxOption>) optionList);
                        try {
                            ipInfo.setMxDone(false);
                            ipInfo.getIpInfoOptions().setResolveMx(true, (List<EMxOption>) optionsList);
                            result.add(ipInfo);
                        } catch (Exception e) {
                            ipInfo.setRunning(false, EDnsOption.MX);
                            ipInfo.setMxDone(true);
                            break;
                        }
                    }
                    break;
                case RDNS:
                    if (!ipInfo.isRunning(EDnsOption.RDNS) && !ipInfo.getIpInfoOptions().isResolveRdns()) {
//                        System.err.println("RDNS: getUnresolvedRequestsFromResultPool: " + ipInfo.getCorrectedQuery());
                        try {
                            ipInfo.getIpInfoOptions().setResolveRdns(true);
                            result.add(ipInfo);
                        } catch (Exception e) {
                            ipInfo.setRunning(false, EDnsOption.RDNS);
                            break;
                        }
                    }
                    break;
                case TXT:
                    if (!ipInfo.isRunning(EDnsOption.TXT) && !ipInfo.getIpInfoOptions().isResolveTxt()) {
//                        System.err.println("TXT: getUnresolvedRequestsFromResultPool: " + ipInfo.getCorrectedQuery());
                        try {
                            ipInfo.getIpInfoOptions().setResolveTxt(true);
                            result.add(ipInfo);
                        } catch (Exception e) {
                            ipInfo.setRunning(false, EDnsOption.TXT);
                            break;
                        }
                    }
                    break;
                default:
                    break;
                }
        }
        if (isAutoAdjustThreadPoolMaximumSize()) {
            autoAdjustThreadPoolMaximumSize(result.size());
        }
        return result;
    }

    /**
     * Expands a string to the specified length by adding whitespaces.
     *
     * @param string String.
     * @param length Desired length.
     * @param rightAlign Adds the whitespaces at the beginning of the string.
     * @return Expanded string.
     */
    public static String expandStringToLength(final String string, final int length, final boolean rightAlign) {
        if (string == null) {
            return "";
        }
        if (string.length() >= length) {
            return string;
        }
        final StringBuilder sb = new StringBuilder(string);
        while (sb.length() < length) {
            if (rightAlign) {
                sb.insert(0, " ");
            } else {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    /**
     * Sets the source of an external IPv4Info configuration file.
     *
     * @param configSource External configuration file.
     */
    public static void setConfigFile(final String configSource) {
        if (configSource == null || configSource.length() == 0) {
            return;
        }
        System.setProperty("IPv4Config", configSource);
        document = null;
        getConfigDocument();
    }

    /**
     * Returns the internal configuration.xml or an external configuration file parsed into a Document-Object.
     *
     * @return The internal configuration.xml or an external configuration file parsed into a Document-Object.
     */
    private static Document getConfigDocument() {
        if (document != null) {
            return document;
        }
        InputStream is = null;
        try {
            if (System.getProperties().containsKey("IPv4Config")) {
                final File file = new File(System.getProperties().getProperty("IPv4Config"));
                if (file.exists()) {
                    //System.err.println("Config: " + System.getProperties().getProperty("IPv4Config"));
                    is = new FileInputStream(file);
                } else {
                    System.getProperties().remove("IPv4Config");
                }
            }
            if (is == null) {
                is = Ipv4Utils.class.getResourceAsStream("DefaultConfig.xml");
            }
            if (document != null) {
	            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
	            document.getDocumentElement().normalize();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ignore) {
                }
            }
        }
        return document;
    }

    /**
     * Returns the MX pitfalls from the configured configuration file.
     *
     * @return MX pitfalls from the configured configuration file.
     */
    public static List<String> getPitfalls() {
    	final List<String> result = new ArrayList<String>();
    	try {
	        final NodeList nodeList = getConfigDocument().getElementsByTagName("pitfall");
	        for (int i = 0; i < nodeList.getLength(); ++i) {
	            final String pitfall = nodeList.item(i).getTextContent().trim();
	            if (pitfall.length() > 0) {
	                result.add(pitfall);
	            }
	        }
    	} catch (Exception e) {
//    		e.printStackTrace();
    	}
        return result;
    }

}
