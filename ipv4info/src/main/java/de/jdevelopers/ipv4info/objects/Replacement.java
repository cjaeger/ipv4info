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

package de.jdevelopers.ipv4info.objects;

/**
 * Object that holds informations for doing text replacements by using the String.replaceAll() function.
 *
 * @author Carsten JÃ¤ger (c.jaeger@jdevelopers.de)
 *
 */

public class Replacement implements Comparable<Replacement> {

    /**
     * Pattern string to look for (normally a regular expression).
     */
    private String pattern;

    /**
     * Replacement string.
     */
    private String replacement;


    /**
     * Constructor.
     */
    public Replacement() {
        super();
    }

    /**
     * Constructor.
     *
     * @param pattern Pattern string to look for (normally a regular expression).
     * @param replacement Replacement string.
     */
    public Replacement(final String pattern, final String replacement) {
        super();
        this.pattern = pattern;
        this.replacement = replacement;
    }

    /**
     * Returns the value of pattern.
     *
     * @return The value of pattern.
     */
    public final String getPattern() {
        return pattern;
    }

    /**
     * Sets the value of pattern.
     *
     * @param pattern The value of pattern.
     */
    public final void setPattern(final String pattern) {
        this.pattern = pattern;
    }

    /**
     * Returns the value of replacement.
     *
     * @return The value of replacement.
     */
    public final String getReplacement() {
        return replacement;
    }

    /**
     * Sets the value of replacement.
     *
     * @param replacement The value of replacement.
     */
    public final void setReplacement(final String replacement) {
        this.replacement = replacement;
    }

    public final int compareTo(final Replacement replacement) {
        return pattern.compareTo(replacement.getPattern());
    }

}
