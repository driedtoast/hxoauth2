#!/bin/sh

PACKAGE_NAME="hxoauth2"

rm "$PACKAGE_NAME.zip" 
mkdir -p dist
cp haxelib.xml dist
cp -R src/* dist
cd dist
zip -b . "$PACKAGE_NAME" *
mv "$PACKAGE_NAME.zip" ../

