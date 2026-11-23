# Ayana in-app test, run by the test app with /system/bin/sh (mksh).
# Environment from the app: LIB (native library dir), R (Debian rootfs),
# TMPDIR (cache dir), HOME (files dir).

RUN="$LIB/libayanarun.so"
PROBE="$LIB/libayanaprobe.so"
TRUEBIN="$LIB/libayanatrue.so"
LD="$R/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
LP="$R/usr/lib/aarch64-linux-gnu"
# The lib dir path contains "=" (/data/app/~~xxx==/...), which env(1) would
# read as a variable assignment. A symlink gives the launcher a clean name;
# exec through it is still an exec of the file in the lib dir.
RUNL="$TMPDIR/ayana-run"
ln -sf "$RUN" "$RUNL"
export RUN RUNL PROBE TRUEBIN LD LP R

sec() { echo; echo "=== $1 ==="; }
run() {  # run "<shell command>" [max_lines]
  echo "\$ $1"
  _o=$(sh -c "$1" 2>&1)
  _rc=$?
  printf '%s\n' "$_o" | head -n "${2:-25}"
  echo "[rc=$_rc]"
}

# A: handler only, real paths.  B: handler + path mapping, Debian sees its own /.
A='"$RUN" "$LD" --library-path "$LP"'
BENV='env -i HOME=/root TERM=dumb LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
B="$BENV"' "$RUNL" --root "$R" /lib/ld-linux-aarch64.so.1 /usr/bin/bash -c'
BT="$BENV"' AYANA_TRACE=1 "$RUNL" --root "$R" /lib/ld-linux-aarch64.so.1 /usr/bin/bash -c'

sec "1. app sandbox"
run 'id; cat /proc/self/attr/current; echo'
run 'getprop ro.build.version.sdk; uname -r; echo "LIB=$LIB"'
run 'grep -E "^(Seccomp|Seccomp_filters|NoNewPrivs)" /proc/self/status'

sec "2. exec rules"
run '"$TRUEBIN"; echo "exec from lib dir rc=$?"'
run 'cp "$TRUEBIN" "$TMPDIR/t" && chmod 700 "$TMPDIR/t"; "$TMPDIR/t"; echo "exec from data dir rc=$?"'
run '/system/bin/linker64 "$TMPDIR/t"; echo "exec via system linker rc=$?"'

sec "3. native probe"
run '"$PROBE"' 80

sec "4. Debian mode A (no path mapping)"
run "AYANA_TRACE=1 $A \"\$R/usr/bin/true\"; echo \"true rc=\$?\""
run "$A \"\$R/usr/bin/uname\" -a"
run "$A \"\$R/usr/bin/cat\" \"\$R/etc/os-release\"" 3

sec "5. Debian mode B (Debian sees its own root)"
run "$BT 'ls /bin/true >/dev/null; echo forked child rc=\$?'"
run "$B 'cat /etc/os-release | head -n 2'"
run "$B 'ls /; ls /usr/bin | wc -l'" 30
run "$B 'grep -i seccomp /proc/self/status'"
run "$B 'id; whoami'"
run "$B 'sh -c \"sh -c \\\"echo nested exec ok\\\"\"'"
run "$B 'mkdir -p /tmp/ayana-t && echo hi > /tmp/ayana-t/a && mv /tmp/ayana-t/a /tmp/ayana-t/b && cat /tmp/ayana-t/b && rm -r /tmp/ayana-t'"
run "$B 'awk \"BEGIN{print 42}\"; ls -l /usr/bin/awk /etc/alternatives/awk'"
run "$B 'cat /etc/resolv.conf; getent hosts deb.debian.org'"
run "$B 'perl -e \"print qq(perl ok\\n)\"'"
run "$B 'dpkg-query -W | wc -l; apt-get --version | head -n 1'"
run "$B 'timeout 120 apt-get update 2>&1 | tail -n 8'" 12
run "$B 'timeout 120 apt-get -o APT::Sandbox::User=root update 2>&1 | tail -n 4'" 8

sec "6. speed"
run "$B 'time ls -lR /usr/share/ >/dev/null'"
run "time $A \"\$R/usr/bin/ls\" -lR \"\$R/usr/share/\" >/dev/null"
run "$B 'time (for i in 1 2 3 4 5 6 7 8 9 10; do /usr/bin/true; done)'"

sec "done"
