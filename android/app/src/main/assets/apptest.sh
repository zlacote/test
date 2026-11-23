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
BF="$BENV"' "$RUNL" --root "$R" --fakeroot /lib/ld-linux-aarch64.so.1 /usr/bin/bash -c'
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

sec "7. fake root, links, cwd"
run "$BF 'id; whoami; ls -ld /etc /root /tmp'"
run "$BF 'readlink /usr/bin/awk /etc/alternatives/awk; awk \"BEGIN{print 42}\"'"
run "$BF 'cd /etc && pwd && /bin/pwd; cd / && /bin/pwd'"
run "$BF 'ln -sf /usr/bin/mawk /tmp/l && readlink /tmp/l && /tmp/l \"BEGIN{print 7}\"; rm /tmp/l'"
run "$BF 'touch /tmp/o && chown 42:42 /tmp/o && echo chown ok && stat -c \"%U %G\" /tmp/o; rm /tmp/o'"

sec "8. apt and real packages"
run "$BF 'ls /etc/apt/apt.conf.d; grep -hv \"^//\" /etc/apt/apt.conf.d/* | head -n 15'" 25
run "$BF 'timeout 180 apt-get -o Debug::RunScripts=true update 2>&1 | tail -n 15; echo apt-update rc=\${PIPESTATUS[0]}'" 20
run "$BF 'time timeout 900 apt-get install -y --no-install-recommends file procps python3 git ca-certificates hostname 2>&1 | grep -vE \"^(Get|Selecting|Preparing|Unpacking|Setting up|Processing)\" | tail -n 25; echo apt-install rc=\${PIPESTATUS[0]}'" 40
run "$BF 'dpkg -l file procps python3 git ca-certificates hostname 2>&1 | tail -n 6'"
run "$BF 'file /bin/bash'"
run "$BF 'ps aux | head -n 5; free -m; uptime'"
run "$BF 'hostname; hostname -I'"
run "$BF 'python3 -c \"import sys,threading; t=threading.Thread(target=print,args=(1,)); t.start(); t.join(); print(sys.version.split()[0])\"'"
run "$BF 'python3 -c \"import multiprocessing as m; print(m.Pool(2).map(abs,[-1,-2]))\" 2>&1 | tail -n 3'"
run "$BF 'ls /etc/ssl/certs | wc -l; cd /tmp && rm -rf t && timeout 120 git clone -q --depth 1 https://github.com/zlacote/test t && cd t && git log --oneline | head -n 1 && git status --short | head -n 3; echo git rc=\$?'"
run "$BF 'timeout 180 apt-get install -y --reinstall hostname 2>&1 | tail -n 6'"
run "$BF 'ldconfig; echo ldconfig rc=\$?; ldconfig -p | head -n 2'"

sec "9. background process limit"
run 'pids=""; i=0; while [ $i -lt 40 ]; do /system/bin/sleep 120 >/dev/null 2>&1 & pids="$pids $!"; i=$((i+1)); done; sleep 25; n=0; for p in $pids; do kill -0 $p 2>/dev/null && n=$((n+1)); done; echo "alive after 25s: $n of 40"; kill $pids 2>/dev/null; true'

sec "done"
