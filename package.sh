#!/bin/sh

PACKAGE_NAME="hxoauth2"

mkdir -p dist
cp haxelib.xml dist
cp -R src/* dist
cd dist
jar cvf "$PACKAGE_NAME.zip" *
mv "$PACKAGE_NAME.zip" ../

