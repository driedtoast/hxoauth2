package ;

import chx.hash.HMAC;
import chx.hash.Sha1;
import haxe.SHA1;
// import neko.Lib;
import hxoauth.OAuth;
import utils.Base64;

/**
 * ...
 * @author Daniel Marchant
 */

class OAuthTest
{

	static function main()
	{

		var consumer_key = "consumerkey" ;
		var consumer_secret = "secret" ;

		var user_key = "username" ;
		var user_secret = "pw" ;

		var server_url = "http://localhost:3000/oauth2/authorize" ;

		var oaClient = OAuth.connect( consumer_key, consumer_secret ) ;
		oaClient.token = new Token(user_key, user_secret) ;
		trace( oaClient.request( server_url, GET ) ) ;

	}

}