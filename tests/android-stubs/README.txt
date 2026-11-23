Compile-only stubs of the few Android APIs used by android/src, for checking
the Java code on a machine without the Android SDK:
  javac -d /tmp/stubs $(find tests/android-stubs -name '*.java')
  javac -cp /tmp/stubs -d /tmp/app $(find android/src -name '*.java')
