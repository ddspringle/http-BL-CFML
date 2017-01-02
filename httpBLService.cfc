/**
*
* @file  httpBLService.cfc
* @author  Denard Springle (denard.springle@gmail.com)  
* @description I provide a CFML interface for the Project Honeypot http:BL DNS blacklist (https://www.projecthoneypot.org/httpbl_api.php)
*
*/

component output="false" displayname="httpBLService" hint="I am a CFML interface for the Project Honeypot http:BL DNS blacklist." {

	/**
	* @displayname	init
	* @description	I am the constructor for the httpBLService
	* @param		accessKey {String} I am the 12-alpha character access key provided by Project Honeypot
	* @param 		debug {Boolean} default: false - I am a flag to debug DNS lookups (true) or not (false)
	* @return		this
	*/
	public function init( string accessKey = '', boolean debug = false ) {
		variables.accessKey = arguments.accessKey;
		variables.debug = arguments.debug;

		return this;
	}

	/**
	* @displayname	checkIp
	* @description	I check the provided IP address with the http:BL service
	* @param		ipAddress {String} I am the IP address to check against the blacklist
	* @return		struct
	*/
	public struct function checkIp( required string ipAddress ) hint="I check the provided IP address with the http:BL service." {
		// var scope the result struct
		var result = structNew();
		// get the results from the http:BL lookup
		var ipBLResult = lookupHost( arguments.accessKey & '.' & reserverIp( arguments.ipAddress ) & '.dnsbl.httpbl.org' );

		// check if zero (0) was returned
		if( !ipBLResult ) {
			// it was, ip non-existent, set dummy result
			result[ 'daysSinceLastActivity' ] = 0;
			result[ 'threatScore' ] = 0;
			result[ 'visitorType' ] = 42; // arbitrary - anything over type id of '7'
			result[ 'comment' ] = 'IP address not found in http:BL';

			// and return the result
			return result;
		}

		// otherwise it's not zero, split the result into an array
		ipBLResult = listToArray( ipBLResult, '.' );

		// assign the values of the array to the result struct
		result[ 'daysSinceLastActivity' ] = ipBLResult[ 2 ]; // days
		result[ 'threatScore' ] = ipBLResult[ 3 ]; // threat
		result[ 'visitorType' ] = ipBLResult[ 4 ]; // type
		// parse the type for the comment
		result[ 'comment' ] = parseType( ipBLResult );

		// and return the result
		return result;

	}

	/**
	* @displayname	parseType
	* @description	I return http:BL specific definitions of type results.
	* @param		blResult {Array} I am the http:BL result after running through listToArray()
	* @return		string
	*/
	public string function parseType( required array blResult ) hint="I return http:BL specific definitions of type results." {
		// var scope the result
		var result = '';

		// switch on the defined type
		switch( arguments.blResult[ 4 ] ) {

			// check if it's a search engine
			case 0:
				// it is, add it to the result
				result = 'Search Engine';

				// then switch on the search engine serial
				// and add it to the result
				switch( arguments.blResult[ 3 ] ) {
					case 1:
						result &= ': AltaVista';
					break;
					
					case 2:
						result &= ': Ask';
					break;
					
					case 3:
						result &= ': Baidu';
					break;
					
					case 4:
						result &= ': Excite';
					break;
					
					case 5:
						result &= ': Google';
					break;
					
					case 6:
						result &= ': Looksmart';
					break;
					
					case 7:
						result &= ': Lycos';
					break;
					
					case 8:
						result &= ': MSN';
					break;
					
					case 9:
						result &= ': Yahoo';
					break;
					
					case 10:
						result &= ': Cull';
					break;
					
					case 11:
						result &= ': InfoSeek';
					break;
					
					case 1:
						result &= ': Miscellaneous';
					break;
				
					default:
						result &= ': undocumented';
					break;
				}

			break;

			// otherwise it's suspicious, harvester, spammer or some combination thereof
			case 1:
				result = 'Suspicious (1)';
			break;

			case 2:
				result = 'Harvester (2)';
			break;

			case 3:
				result = 'Suspicious & Harvester (1+2)';
			break;

			case 4:
				result = 'Comment Spammer (4)';
			break;

			case 5:
				result = 'Suspicious & Comment Spammer (1+4)';
			break;

			case 6:
				result = 'Harvester & Comment Spammer (2+4)';
			break;

			case 7:
				result = 'Suspicious & Harvester & Comment Spammer (1+2+4)';
			break;
		
			default:
				result = 'undocumented';
			break;
		}

		// return the result of the parse
		return result;
	}

	/**
	* @displayname	lookupHost
	* @description	I perform the DNS lookup of the host
	* @param		host {String} I am the host to return DNS results for
	* @return		string
	*/
	public string function lookupHost( required string host ) hint="I perform the DNS lookup of the host." {
		// create a java InetAddress instance
		var inetAddressObj = createObject( 'java', 'java.net.InetAddress' );
		var dnsResult = '';

		// try
		try {
			// to get the host address information
			dnsResult = inetAddressObj.getByName( arguments.host ).getHostAddress();
		// catch any errors
		} catch( any e ) {
			// check if we're in debug mode
			if( arguments.debug ) {
				// we are, rethrow the error
				rethrow;
			// otherwise
			} else {
				// we're not, return zero
				dnsResult = 0;				
			}
		}

		// return the result string
		return dnsResult;
	}

	/**
	* @displayname	reverseIp
	* @description	I reverse the order of an ip address
	* @param		ipAddress {String} I am the IP address to reverse
	* @return		string
	*/
	public string function reverseIp( required string ipAddress ) hint="I return an IP address in reverse dotted order." {
		// convert the ip address to an array
		var ipArray = listToArray( arguments.ipAddress, '.' );
		// set up another array to hold the reverse
		var revIpArray = arrayNew( 1 );

		// loop backwards through the ipArray
		for( var i = 4; i>=1; i-- ) {
			// and append this value to the reversed ip array
			// NOTE: requires ACF11+ or Lucee 4.5+ 
			// Change to 'revIpArray = arrayAppend( revIpArray, ipArray[ i ] );' on older versions
			revIpArray.append( ipArray[ i ] );
		}

		// return the reversed ip array converted back to an ip address format
		return arrayToList( revIpArray, '.' );
	}

}