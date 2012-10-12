package hxoauth;
import chx.hash.HMAC;
import chx.hash.Sha1;
import haxe.Http;
import haxe.Int32;
import haxe.io.Bytes;
import haxe.Timer;
import utils.Base64;

/**
 * ...
 * @author Renaud Bardet
 */

enum SignatureMethod {
	
	//PlainText ;
	HMAC_SHA1 ;
	//RSA_SHA1 ;
	
}

enum HTTPMethod {
	
	GET ;
	POST ;
	PUT ;
	DELETE ;
	
}

using Lambda ;

class OAuth
{

	public static function connect( _key : String, _secret: String )
	{
		
		return new Client( new Consumer( _key, _secret ) ) ;
		
	}
	
}

class Client
{
	
	public var consumer(default, null) : Consumer ;
	public var token : Null<Token> ;
	public var signature : SignatureMethod ;
	
	public function new( _consumer : Consumer )
	{
		
		consumer = _consumer ;
		signature = HMAC_SHA1 ;
		
	}
	
	public function request( _uri : String, ?_method : HTTPMethod, ?_postData : Dynamic )
	{
		
		if ( token == null )
			throw "Cannot request with unauthenticated user" ;
		
		var req = new Request( _uri, consumer, token, _method, _postData ) ;
		
		req.sign( signature ) ;
		
		trace( req.dump() ) ;
		
		return req.send() ;
		
	}
	
}

class Request
{
	
	private var consumer : Consumer ;
	private var token : Token ;
	
	private var scheme : String ;
	private var authority : String ;
	private var path : String ;
	private var query : String ;
	private var fragment : String ;
	
	private var method : HTTPMethod ;
	
	private var credentials : Hash<String> ;
	
	private var signature : SignatureMethod ;
	
	private var data : String ;
	
	public function new( _uri : String, _consumer : Consumer, ?_token : Token, ?_method : HTTPMethod, ?_data : String )
	{
		
		consumer = _consumer ;
		token = _token ;
		
		// see http://tools.ietf.org/html/rfc3986#page-50
		var uriReg = ~/^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/ ;
		
		if ( !uriReg.match( _uri ) )
			throw "Malformed URI" ;
		
		scheme = uriReg.matched( 2 ) ;
		authority = uriReg.matched( 4 ) ;
		path = uriReg.matched( 5 ) ;
		query = uriReg.matched( 7 ) ;
		fragment = uriReg.matched( 9 ) ;
		
		/*// strip default port values from authority
		var portReg = ~/^([^:]*):([0-9]*)/ ;
		if ( portReg.match( authority ) )
		{
			
			var port = portReg.matched( 2 ) ;
			var host = portReg.matched( 1 ) ;
			
			if ( ( scheme == "http" && port == "80" ) || ( scheme == "https" && port == "443" ) )
				authority = host ;
			
		}*/
		
		method = ( _method != null ) ? _method : GET ;
		
		data = _data ;
		
		signature = HMAC_SHA1 ;
		
		credentials = new Hash<String>() ;
		credentials.set( "oauth_consumer_key", _consumer.key ) ;
		credentials.set( "oauth_token", _token.key ) ;
		credentials.set( "oauth_signature_method", signatureToString(signature)  ) ;
		credentials.set( "oauth_timestamp", "1340982010" ) ;//'' + timestamp() ) ;
		credentials.set( "oauth_nonce", "ripple" ) ;//generateNonce() ) ;
		credentials.set( "oauth_version", "1.0" ) ;
		
	}
	
	public function sign( ?_method : SignatureMethod )
	{
		
		signature = ( _method != null ) ? _method : HMAC_SHA1 ;
		
		credentials.set( "oauth_signature_method", signatureToString(signature) ) ;
		
		switch( _method )
		{
			
			case HMAC_SHA1 :
				var text = baseString() ;
				trace( text ) ;
				var key = encode( consumer.secret ) + '&' + encode( token.secret ) ;
				trace( key ) ;
				var hash = new HMAC( new Sha1() ) ;
				var bytes = hash.calculate( Bytes.ofString(key), Bytes.ofString(text) );
				trace( bytes.toHex() ) ;
				var digest = Base64.encode( bytes.toString() ) ;
				trace( digest ) ;
				credentials.set( "oauth_signature", digest ) ;
			
		}
		
	}
	
	public function send() : String
	{
		
		switch( method )
		{
			
			case GET :
				trace(dump()) ;
				var h = new Http( uri() ) ;
				h.setHeader( "Authorization", composeHeader() ) ;
				var ret = '' ;
				h.onData = function(d) ret = d ;
				h.onStatus = function(i) trace( "Status : " + i ) ;
				//h.on
				h.request( false ) ;
				return ret ;
			
			default : 
				return '' ;
			
		}
		
	}
	
	public function dump() : String
	{
		
		//trace( baseString() ) ;
		
		return
			methodToString(method) + ' ' + path + ((query != null) ? ('?' + query) : '') + ((fragment != null)?('#'+fragment):'') + " HTTP/1.1\n"
			+ "Host: " + authority + '\n'
			+ "Authorization: " + composeHeader() ;
		
	}
	
	private function uri()
	{
		
		var buf = new StringBuf() ;
		buf.add( scheme ) ;
		buf.add( "://" ) ;
		buf.add( authority ) ;
		buf.add( path ) ;
		if ( query != null && query != '' )
		{
			buf.add( '?' ) ;
			buf.add( query ) ;
		}
		if ( fragment != null && fragment != '' )
		{
			buf.add( '#' ) ;
			buf.add( fragment ) ;
		}
		
		return buf.toString() ;
		
	}
	
	private function composeHeader()
	{
		
		var buf = new StringBuf() ;
		
		buf.add( "OAuth " ) ;
		
		var params = credentials.keys() ;
		for ( p in params )
		{
			
			buf.add( encode( p ) ) ;
			buf.add( "=\"" ) ;
			buf.add( encode( credentials.get( p ) ) ) ;
			buf.add( '"' ) ;
			if ( params.hasNext() )
				buf.add( ',' ) ;
			
		}
		
		return buf.toString() ;
		
	}
	
	private function baseString() : String
	{
		
		var buf = new StringBuf() ;
		
		buf.add( methodToString( method ) ) ;
		buf.add( '&' ) ;
		buf.add( baseStringURI() ) ;
		buf.add( '&' ) ;
		buf.add( encode(baseStringParameters()) ) ;
		
		return buf.toString() ;
		
	}
	
	private function baseStringURI() : String
	{
		
		var buf = new StringBuf() ;
		
		buf.add( scheme.toLowerCase() ) ;
		buf.add( "://" ) ;
		var portReg = ~/^([^:]*):([0-9]*)/ ;
		var host = if( portReg.match( authority ) )
				portReg.matched( 1 ) ;
			else
				authority ;
		buf.add( host.toLowerCase() ) ;
		buf.add( path ) ;
		
		trace( buf.toString() ) ;
		
		return encode( buf.toString() ) ;
		
	}
	
	public function baseStringParameters() : String
	{
		
		// do not use a Hash as identically named parameters MUST appear twice
		var params = new Array<{k: String, v : String}>() ;
		
		function separateKV( _s )
		{
			var kv = _s.split( '=' ) ;
			if ( kv[1] == null ) kv[1] = '' ;
			return { k : encode( kv[0] ), v : encode( kv[1] ) } ;
		}
		
		if ( query != null )
		{
			for ( pair in query.split('&').map( separateKV ) )
				params.push( pair ) ;
		}
		
		// TODO
		// do the same with data if it's complient with x-www-form-urlencoded
		
		for ( k in credentials.keys() )
		{
			
			if ( k != "realm" && k != "oauth_signature" )
				params.push( { k : encode( k ), v : encode( credentials.get(k) ) } ) ;
			
		}
		
		params.sort(
			function( _x1 : { k : String, v : String }, _x2 : { k : String, v : String } )
			{
				
				return if ( _x1.k < _x2.k )
						-1 ;
					else if ( _x1.k > _x2.k )
						1 ;
					else if ( _x1.v < _x2.v )
						-1 ;
					else
						1 ;
				
			} ) ;
		
		function joinKV( _ : { k : String, v : String } ) return _.k + '=' + _.v ;
		
		return params.map( joinKV ).join( '&' ) ;
		
	}
	
	private static inline function methodToString( _m : HTTPMethod ) : String
	{
		
		return switch( _m )
		{
			
			case GET	: "GET" ;
			case POST	: "POST" ;
			case PUT	: "PUT" ;
			case DELETE	: "DELETE" ;
			
		}
		
	}
	
	private static inline function signatureToString( _s : SignatureMethod ) : String
	{
		
		return switch( _s )
		{
			
			case HMAC_SHA1	: "HMAC-SHA1" ;
			//case RSA_SHA1	: "RSA-SHA1" ;
			//case PlainText	: "PLAINTEXT" ;
			
		}
		
	}
	
	private static inline function generateNonce()
	{
		
		var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ;
		var nonce = '' ;
		for ( i in 0...6 )
			nonce += chars.substr( Std.int( Math.random() * chars.length ), 1 ) ;
		
		return nonce ;
		
	}
	
	private static inline function encode( _s : String )
	{
		
		// StringTools.urlEncode might need to be changed to a more strict and less platform dependant encoding
		return StringTools.urlEncode( _s ) ;
		
	}
	
	private static function timestamp() : Int32
	{
		
		#if neko
		var t = Std.int( Timer.stamp() ) ;
		return Int32.make( ( t >> 16 ) & 0x7FFF, t & 0xFFFF ) ;
		#else
		return Int32.ofInt( Std.int( Timer.stamp() ) ) ;
		#end
		
	}
	
}

class Consumer
{
	
	public var key(default, null) : String ;
	public var secret(default, null) : String ;
	
	public function new( _key : String, _secret : String )
	{
		
		key = _key ;
		secret = _secret ;
		
	}
	
	public function toString() : String
	{
		
		
		
	}
	
}

class Token
{
	
	public var key(default, null) : String ;
	public var secret(default, null) : String ;
	//public var callbackConfirmed(default, null) : Bool ;
	
	//public var callbackUrl(default, setCallback) : String ;
	//public var verifier(default, setVerifier) : String ;
	
	public function new( _key, _secret)
	{
		
		key = _key ;
		secret = _secret ;
		
		//callback_confirmed = false ;
		
	}
	
	//private function setCallback( _url : String )
	//{
		//callback_url = _c ;
		//callback_confirmed = true ;
	//}
	//
	//private function setVerifier( ?_v : String )
	//{
		//
		//if ( _v != null )
			//verifier = _v ;
		//else
			//verifier = generateVerifier() ;
		//
	//}
	
}