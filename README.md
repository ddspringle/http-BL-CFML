# http:BL CFML
This repository includes a CFC called httpBLService.cfc that makes use of the Project Honeypot http:BL DNS Blacklist - this blacklist maintains the IP addresses of known spammers, email harvesters and other suspicious activities.

## Usage

To use this wrapper, simply initialize it with your 12-alpha character access key provided by Project Honeypot, as follows:

    // get the httpBLService
    httpBLService = createObject( 'component', 'model.services.httpBLService').init( accessKey = '[YOUR_ACCESS_KEY]' [, debug=true] );

If you pass the optional argument `debug=true` then any errors that occur during DNS lookup will be rethrown instead of ignored. 

You then call the service with the IP address you wish to check, as follows:

    // get the structure as a variable from the httpBL service    
	returnStruct = httpBLService.checkIp( ipAddress = [IP_ADDRESS_TO_CHECK] );

This returns:

    daysSinceLastActivity: the days since this IP address was last seen hitting a honey pot
    threatScore: the threat posed by this IP address, from 0 - 255 (see the http:BL API docs for more details)
    visitorType: this is a numeric representation of what the visitor did to get flagged in the blacklist
    comment: additional details on the visitor type

**NOTE**: You should [read the http:BL API documentation](https://www.projecthoneypot.org/httpbl_api.php) for more information on what these values mean. Some key things to know is that a visitor type of zero (0) indentifies a known search engine (so don't block those if you want to be indexed) and a vistor type of 42 identifies an IP that was *not* found in the blacklist.

## Compatibility

* Adobe ColdFusion 11+ (now uses some member functions)
* Lucee 4.5+

## Bugs and Feature Requests

If you find any bugs or have a feature you'd like to see implemented in this code, please use the issues area here on GitHub to log them.

## Contributing

This project is actively being maintained and monitored by Denard Springle. If you would like to contribute to this project please feel free to fork, modify and send a pull request!

## License

The use and distribution terms for this software are covered by the Apache Software License 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
