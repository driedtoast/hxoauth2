package utils;
import haxe.io.Bytes;
import haxe.io.BytesBuffer;
import haxe.SHA1;

/**
 * ...
 * @author Renaud Bardet
 */

class HMAC 
{

	public static function sha1( _key : String, _data : String )
	{
		
		return encrypt( SHA1.encode, 64, 20, _key, _data ) ;
		
	}
	
	public static function encrypt( _hash : String->String, _block_length : Int, _out_length : Int, _key : String, _data : String )
	{
		
		if ( _key.length > _block_length )
			_key = _hash( _key ) ;
		
		var ibuf = new BytesBuffer() ;
		var obuf = new BytesBuffer() ;
		
		for ( i in 0..._block_length )
		{
			ibuf.addByte( 0x36 ) ;
			obuf.addByte( 0x5C ) ;
		}
		
		var ipad = ibuf.getBytes() ;
		var opad = obuf.getBytes() ;
		
		var bkey = Bytes.ofString( _key ) ;
		var tbuf = new BytesBuffer() ;
		tbuf.add( Bytes.ofString( _key ) ) ;
		for( i in 0...(_block_length - bkey.length) )
			tbuf.addByte(0) ;
		bkey = tbuf.getBytes() ;
		
		var h1 = bytesOfHex( _hash( xor( bkey, ipad ).toString() + _data ) ).toString() ;
		
		var h2 = _hash( xor( bkey, opad ).toString() + h1 ) ;
		
		return h2 ;
		
	}
	
	private static inline function xor( _b1 : Bytes, _b2 : Bytes ) : Bytes
	{
		
		var byteBuf = new BytesBuffer() ;
		
		var maxLength = _b1.length ;
		if ( _b2.length > maxLength )
			maxLength = _b2.length ;
		
		for ( i in 0...maxLength )
			byteBuf.addByte( nonNull( _b1.get(i) ) ^ nonNull( _b2.get(i) ) ) ;
		
		return byteBuf.getBytes() ;
		
	}
	
	private static function nonNull(_i : Int)
	#if flash9
	return _i
	#else
	return _i != null ? _i : 0
	#end
	
	private static function bytesOfHex( _hex : String ) : Bytes
	{
		
		var buf = new BytesBuffer() ;
		if ( _hex.length % 2 == 1 )
			_hex = '0' + _hex ;
		
		for ( i in 0...Std.int(_hex.length/2) )
			buf.addByte( Std.parseInt( '0x' + _hex.substr( i * 2, 2 ) ) ) ;
		
		return buf.getBytes() ;
		
	}
	
}