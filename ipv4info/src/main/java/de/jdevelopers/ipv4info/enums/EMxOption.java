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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Enumeration of possible MX request options.
 *
 * @author Carsten JÃ¤ger (c.jaeger@jdevelopers.de)
 *
 */
public enum EMxOption {

    /**
     * Checks the root entry if it hears on port 25.
     *
     * There are at most about 1% of all domains that have no valid MX entry but hear on port 25.
     * And of this 1% there may be another 1% that allows relaying mails. So there is no real reason to resolve them.
     * So this option is definitively NOT RECOMMENDED, because it slows down the resolving process very much!
     * Therefore it isn't included in any of the predefined option sets.
     *
     * If you want to use this option, you have to create your an individual option set.
     */
    CHECK_ROOT,

    /**
     * Return domains/IP's that are already resolved with another priority.
     * The isDoublet and hasDoublet flags are set for the all doublet domains.
     * Because finding out which domains/IP's are a doublet and marking them, this option is more time expensive.
     *
     * The usage of this option is NOT recommended!
     */
    MARK_DOUBLETTES,

    /**
     * Recheck MX entries on a SocketTimeoutException.
     */
    RETRY,

    /**
     * Resolve IP-Adresses of the found MX domains.
     */
    RESOLVE_IPS,

    /**
     * Won't return domains that are suspected as a blackhole.
     */
    SKIP_BLACKHOLES,

    /**
     * Won't return domains that are marked as disabled.
     */
    SKIP_DISABLED,

    /**
     * Won't return domains/IP's that are already resolved with another priority.
     *
     * It will not search for the domain/IP that was resolved first just to set the hasDoublet flag of the
     * corresponding MxResult-Object. If no individual MX resolve flags are set, or in this set the
     * SKIP_DOUBLETTES_MARK option wasn't found.
     */
    SKIP_DOUBLETTES,

    /**
     * Won't return domains that are marked as pitfalls.
     */
    SKIP_PITFALLS,

    /**
     * Won't return domains, that are alive, but refused a connection on VERIFY_DOMAIN or VERIFY_IPS.
     *
     * To use this option is NOT RECOMMENDED, so it's not included in any of the predefined option sets.
     * If you want to use this option, you have to create your an individual option set.
     */
    SKIP_REFUSED,

    /**
     * Won't return entries which are not reachable (requires VERIFY_DOMAIN and/or VERIFY_IPS).
     */
    SKIP_UNREACHABLE,

    /**
     * Verifies the reachability of the resolved domains.
     */
    VERIFY_DOMAIN,

    /**
     * Verifies the reachability of the resolved domains.
     */
    VERIFY_IPS;


    /*
     *  Some predefined option sets to resolve MX entries.
     *  To have full control of what is being resolved, create your own option set...
     */

    /**
     * Returns all available MX resolving and skip options.
     *
     * @return All available MX resolving and skip options.
     */
    public static List<EMxOption> getAllOptions() {
        return new ArrayList<EMxOption>(Arrays.asList(values()));
    }

    /**
     * Returns all possible MX resolving options without any skip option.
     *
     * @return All possible MX resolving options without any skip option.
     */
    public static List<EMxOption> getAllResolveOptions() {
        final List<EMxOption> result = new ArrayList<EMxOption>();
        result.add(RETRY);
        result.add(RESOLVE_IPS);
        result.add(VERIFY_DOMAIN);
        result.add(VERIFY_IPS);
        return result;
    }

    /**
     * Returns the MX resolve options which include all skips.
     *
     * @return MX resolve options which include all skips.
     */
    public static List<EMxOption> getSkipOptions() {
        final List<EMxOption> result = new ArrayList<EMxOption>();
        result.add(SKIP_BLACKHOLES);
        result.add(SKIP_DISABLED);
        result.add(SKIP_DOUBLETTES);
        result.add(SKIP_PITFALLS);
        return result;
    }

    /**
     * Returns the default MX resolve options.
     *
     * This option set skips unreachable entries!
     * Skipping unreachable entries may not the choice for everyone, because an unreachable domain may be reachable
     * at a later time. If you want to include unreachable domains, use the getCommonOptions() function,
     * or create your own option set.
     *
     * @param skipUnreachable {@code true} to skip entries that are not reachable, otherwise {@code false}.
     * @return Default MX resolve options.
     */
    public static List<EMxOption> getDefaultOptions(final boolean skipUnreachable) {
        final List<EMxOption> result = getSkipOptions();
        result.add(RETRY);
        result.add(VERIFY_DOMAIN);
        if (skipUnreachable) {
            result.add(EMxOption.SKIP_UNREACHABLE);
        }
        return result;
    }

    /**
     * Returns a list of EMxOptions from a given String or String array.
     *
     * @param optionStrings String or String array to parse for EMxOptions.
     * @return List of EMxOptions.
     */
    public static List<EMxOption> getOptionsFromString(final String... optionStrings) {
        final List<EMxOption> result = new ArrayList<EMxOption>();
        if (optionStrings == null || optionStrings.length == 0) {
            return result;
        }
        for (final String optionString : optionStrings) {
            if (optionString != null) {
                for (final String option : optionString.toUpperCase().split("[\\s,]+")) {
                    try {
                        result.add(EMxOption.valueOf(option.trim()));
                    } catch (Exception ignore) { }
                }
            }
        }
        return result;
    }

}
