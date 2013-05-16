IPv4Info 0.5.0
==============

<b>Java library for getting DNS-Informations of IPv4-Addresses, IPv4-Subnets E-Mail-Addresses or Domains.</b>


Input can be a list of follwing types:

- IPv4-Address
- IPv4-Subnet
- E-Mail-Address
- Domain

Following DNS-Lookup's are supported:

- <b>A</b> (always)
- <b>RDNS</b> (optional)
- <b>MX</b> (optional)
- <b>TXT</b> (optional)


<p><i>Usage sample:</i></p>
<pre>
...  
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
 * This will just do a BASIC lookup which just resolves the A-Record (if needed),
 * to test if the quey is a resolvable domain or IP.
 */
System.out.println("##### Single result: #####");
System.out.println(ipv4Info.getResult("gmail.com"));

/* Set additional lookup types.
 * Setting a type will start the appropriate lookup process in the background.
 * Already resolved entries will be updated/enriched.
 */
ipv4Info.setResolveRdns(true);
ipv4Info.setResolveMx(true, EMxOption.getDefaultOptions(true));
ipv4Info.setResolveTxt(true);

/* Query all results at once.
 * Accessing a result will block the program, until the result is completly resolved!
 * If it's completly resolved in the meanwhile, nothing is blocked anymore, because it's cached in
 * a result pool.
 */  
System.out.println("##### All results: #####");
for (final IpInfo info : ipv4Info.getResults(testCollection)) {
	System.out.println(info);
}

/*
 * Shutdown the internal Thread-Pool.
 * It will shutdown automatically, if it's not used for 60 seconds.
 * To shutdown it immediately, call the shutDownThreadPool()-Method.
 */
Ipv4Utils.shutDownThreadPool();
...
</pre>
