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

import java.util.ArrayList;
import java.util.Collection;

import de.jdevelopers.ipv4info.Ipv4Info;
import de.jdevelopers.ipv4info.enums.EMxOption;
import de.jdevelopers.ipv4info.objects.IpInfo;
import de.jdevelopers.ipv4info.utils.Ipv4Utils;

public class TestIPv4Info {

	public static void main(final String[] args) {

		/*
		 * Preparing the queries.
		 */
		final Collection<String> testCollection = new ArrayList<String>();

		testCollection.add("noname@github.com");
		testCollection.add("gmail.com");
		testCollection.add("212.227.222.8");

		/*
		 * Creating an Ipv4Info instance.
		 */
		final Ipv4Info ipv4Info = new Ipv4Info();

		/*
		 * Adding the queries.
		 */
		ipv4Info.addQueries(testCollection);

		/*
		 * Query a apecifiy result without setting any optional lookyp types.
		 * This will just do a BASIC lookup which just resolves the A-Record (if
		 * needed), to test if the quey is a resolvable domain or IP.
		 */
		System.out.println("##### Single result: #####");
		System.out.println(ipv4Info.getResult("gmail.com"));

		/*
		 * Set additional lookup types. Setting a type will start the
		 * appropriate lookup process in the background. Already resolved
		 * entries will be updated/enriched.
		 */
		ipv4Info.setResolveRdns(true);
		ipv4Info.setResolveMx(true, EMxOption.getDefaultOptions(true));
		ipv4Info.setResolveTxt(true);

		/*
		 * Query all results at once. Accessing a result will block the program,
		 * until the result is completly resolved! If it's completly resolved in
		 * the meanwhile, nothing is blocked anymore, because it's cached in a
		 * result pool.
		 */
		System.out.println("##### All results: #####");
		for (final IpInfo info : ipv4Info.getResults(testCollection)) {
			System.out.println(info);
		}

		/*
		 * Shutdown the internal Thread-Pool. It will shutdown automatically, if
		 * it's not used for 60 seconds. To shutdown it immediately, call the
		 * shutDownThreadPool()-Method.
		 */
		Ipv4Utils.shutDownThreadPool();
	}

}
