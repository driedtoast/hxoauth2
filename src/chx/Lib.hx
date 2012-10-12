/*
 * Copyright (c) 2009, The Caffeine-hx project contributors
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CAFFEINE-HX PROJECT CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE CAFFEINE-HX PROJECT CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package chx;

/**
	Common library functions.
**/
class Lib {

	/**
	 * Load a dynamic library.
	 * @param	lib
	 * @param	prim
	 * @param	nargs
	 * @return
	 * @todo Flash: url loader to swf libs
	 * @todo JS: possibilities?
	 */
	public static function load( lib : String, prim : String, nargs : Int ) : Dynamic {
		#if cpp
			#if iphone
				return loadLazy(lib,prim,nargs);
			#else
				return untyped __global__.__loadprim(lib,prim,nargs);
			#end
		#elseif neko
			return untyped __dollar__loader.loadprim((lib + "@" + prim).__s, nargs);
		#else
			return null;
		#end
	}

	/**
	 * Tries to load a dynamic library, and always returns a valid function,
	 * but the function may throw if called.
	 * @param	lib
	 * @param	prim
	 * @param	nargs
	 * @return
	 */
	public static function loadLazy(lib : String, prim : String, nargs : Int) : Dynamic {
		#if cpp
			try {
				return untyped __global__.__loadprim(lib,prim,nargs);
			} catch( e : Dynamic ) {
				switch(nargs) {
				case 0 : return function() { throw e; };
				case 2 : return function(_1,_2) { throw e; };
				case 3 : return function(_1,_2,_3) { throw e; };
				case 4 : return function(_1,_2,_3,_4) { throw e; };
				case 5 : return function(_1,_2,_3,_4,_5) { throw e; };
				default : return function(_1) { throw e; };
				}
			}
		#elseif neko
			try {
				return load(lib,prim,nargs);
			} catch( e : Dynamic ) {
				return untyped __dollar__varargs(function(_) { throw e; });
			}
		#else
			return null;
		#end
	}

#if neko
	static var __serialize = load("std","serialize",1);
	static var __unserialize = load("std", "unserialize", 2);
#end
}