package dev.ayana.test;

import android.app.Activity;
import android.content.ContentValues;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.provider.Settings;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

/**
 * Test app for the "new rules" app sandbox (targetSdk 35). Unpacks a Debian
 * rootfs from the APK, then runs assets/apptest.sh with /system/bin/sh and
 * saves the output to Download/.
 */
public class MainActivity extends Activity {
    private TextView log;
    private ScrollView scroll;
    private Button button;
    private final StringBuilder report = new StringBuilder();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setFitsSystemWindows(true);
        button = new Button(this);
        button.setText("Run tests");
        button.setOnClickListener(v -> start());
        log = new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(10);
        log.setTextIsSelectable(true);
        scroll = new ScrollView(this);
        scroll.addView(log);
        root.addView(button);
        root.addView(scroll, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
    }

    private void start() {
        button.setEnabled(false);
        report.setLength(0);
        log.setText("");
        new Thread(this::work).start();
    }

    private void append(String line) {
        synchronized (report) {
            report.append(line).append('\n');
        }
        runOnUiThread(() -> {
            log.append(line + "\n");
            scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

    private void work() {
        try {
            File rootfs = new File(getFilesDir(), "rootfs");
            // v2: absolute symlinks are stored with the rootfs prefix.
            File marker = new File(getFilesDir(), "rootfs-v2.ok");
            //noinspection ResultOfMethodCallIgnored
            new File(getFilesDir(), "rootfs.ok").delete();
            if (!marker.exists()) {
                append("extracting Debian rootfs (first run only)...");
                deleteTree(rootfs);
                long t0 = System.currentTimeMillis();
                try (InputStream in = getAssets().open("rootfs.tar")) {
                    extractTar(in, rootfs, rootfs.getAbsolutePath());
                }
                writeText(new File(rootfs, "etc/resolv.conf"), "nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
                writeText(new File(rootfs, "etc/hosts"), "127.0.0.1 localhost\n::1 localhost\n");
                if (!marker.createNewFile()) append("warning: cannot create marker");
                append("extracted in " + (System.currentTimeMillis() - t0) + " ms");
            }
            append("phantom process monitor setting: "
                    + Settings.Global.getString(getContentResolver(), "settings_enable_monitor_phantom_procs"));
            File script = new File(getFilesDir(), "apptest.sh");
            try (InputStream in = getAssets().open("apptest.sh"); OutputStream out = new FileOutputStream(script)) {
                copy(in, out, -1);
            }
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", script.getAbsolutePath());
            pb.redirectErrorStream(true);
            Map<String, String> env = pb.environment();
            env.put("LIB", getApplicationInfo().nativeLibraryDir);
            env.put("R", rootfs.getAbsolutePath());
            env.put("TMPDIR", getCacheDir().getAbsolutePath());
            env.put("HOME", getFilesDir().getAbsolutePath());
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) append(line);
            }
            append("[script exit " + p.waitFor() + "]");
        } catch (Throwable e) {
            append("ERROR: " + e);
        }
        saveReport();
        runOnUiThread(() -> button.setEnabled(true));
    }

    private void saveReport() {
        String name = "ayana-apk-report-" + new SimpleDateFormat("HHmmss", Locale.US).format(new Date()) + ".txt";
        try {
            ContentValues cv = new ContentValues();
            cv.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
            cv.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            cv.put(MediaStore.MediaColumns.RELATIVE_PATH, "Download/");
            Uri uri = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
            if (uri == null) throw new IOException("MediaStore insert failed");
            String text;
            synchronized (report) {
                text = report.toString();
            }
            try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                if (os == null) throw new IOException("cannot open " + uri);
                os.write(text.getBytes(StandardCharsets.UTF_8));
            }
            append("report saved to Download/" + name);
        } catch (Throwable e) {
            append("cannot save report: " + e);
        }
    }

    // ------------------------------------------------------------------
    // files

    private static void writeText(File f, String s) throws IOException {
        File parent = f.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) throw new IOException("mkdir " + parent);
        if (isSymlink(f) && !f.delete()) throw new IOException("unlink " + f);
        try (OutputStream out = new FileOutputStream(f)) {
            out.write(s.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static boolean isSymlink(File f) {
        try {
            return OsConstants.S_ISLNK(Os.lstat(f.getPath()).st_mode);
        } catch (ErrnoException e) {
            return false;
        }
    }

    private static void deleteTree(File f) {
        try {
            int mode = Os.lstat(f.getPath()).st_mode;
            if (OsConstants.S_ISDIR(mode)) {
                Os.chmod(f.getPath(), 0700);
                File[] children = f.listFiles();
                if (children != null) for (File c : children) deleteTree(c);
            }
        } catch (ErrnoException e) {
            return;
        }
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private static void copy(InputStream in, OutputStream out, long limit) throws IOException {
        byte[] buf = new byte[1 << 16];
        long left = limit;
        while (limit < 0 || left > 0) {
            int want = limit < 0 ? buf.length : (int) Math.min(buf.length, left);
            int n = in.read(buf, 0, want);
            if (n < 0) {
                if (limit < 0) return;
                throw new IOException("unexpected end of stream");
            }
            out.write(buf, 0, n);
            left -= n;
        }
    }

    // ------------------------------------------------------------------
    // minimal tar reader (ustar, GNU long names, pax path/linkpath)

    /** Top-level directories that the launcher maps into the rootfs (same rule as map_path). */
    private static final String[] MAPPED = {"etc", "usr", "bin", "sbin", "lib", "lib64", "var", "opt",
            "root", "home", "tmp", "srv", "run", "mnt", "media", "boot"};

    /** Absolute symlink targets inside the mapped tree get the rootfs prefix, so the kernel resolves them there. */
    private static String linkTarget(String link, String prefix) {
        if (prefix == null || !link.startsWith("/")) return link;
        if (link.equals("/")) return prefix;
        String first = link.substring(1).split("/", 2)[0];
        for (String m : MAPPED) if (m.equals(first)) return prefix + link;
        return link;
    }

    private static void extractTar(InputStream raw, File dest, String linkPrefix) throws IOException, ErrnoException {
        InputStream in = new BufferedInputStream(raw, 1 << 16);
        byte[] h = new byte[512];
        String longName = null, longLink = null, paxPath = null, paxLink = null;
        if (!dest.isDirectory() && !dest.mkdirs()) throw new IOException("mkdir " + dest);
        while (readFully(in, h)) {
            if (isZero(h)) break;
            String name = cstr(h, 0, 100);
            String link = cstr(h, 157, 100);
            if (cstr(h, 257, 5).equals("ustar")) {
                String prefix = cstr(h, 345, 155);
                if (!prefix.isEmpty()) name = prefix + "/" + name;
            }
            long size = number(h, 124, 12);
            int mode = (int) number(h, 100, 8);
            char type = (char) h[156];
            if (type == 'x' || type == 'g' || type == 'L' || type == 'K') {
                byte[] data = new byte[(int) size];
                if (!readFully(in, data)) throw new IOException("truncated tar");
                skip(in, pad(size));
                if (type == 'L') longName = cstr(data, 0, data.length);
                else if (type == 'K') longLink = cstr(data, 0, data.length);
                else if (type == 'x') {
                    String[] pl = parsePax(data);
                    if (pl[0] != null) paxPath = pl[0];
                    if (pl[1] != null) paxLink = pl[1];
                }
                continue;
            }
            if (paxPath != null) name = paxPath;
            else if (longName != null) name = longName;
            if (paxLink != null) link = paxLink;
            else if (longLink != null) link = longLink;
            paxPath = paxLink = longName = longLink = null;

            name = clean(name);
            File f = name == null ? null : (name.isEmpty() ? dest : new File(dest, name));
            if (f == null) {
                skip(in, size + pad(size));
                continue;
            }
            File parent = f.getParentFile();
            if (parent != null && !parent.isDirectory()) parent.mkdirs();
            switch (type) {
                case '5':
                    if (!f.isDirectory() && !f.mkdirs()) throw new IOException("mkdir " + f);
                    Os.chmod(f.getPath(), (mode & 0777) | 0700);
                    skip(in, size + pad(size));
                    break;
                case '2':
                    if (isSymlink(f) || f.exists()) f.delete();
                    Os.symlink(linkTarget(link, linkPrefix), f.getPath());
                    skip(in, size + pad(size));
                    break;
                case '1': {
                    String target = clean(link);
                    if (target != null) {
                        File src = new File(dest, target);
                        try (InputStream s = new FileInputStream(src); OutputStream o = new FileOutputStream(f)) {
                            copy(s, o, -1);
                        }
                        Os.chmod(f.getPath(), (mode & 0777) | 0600);
                    }
                    skip(in, size + pad(size));
                    break;
                }
                case '0':
                case '\0':
                case '7':
                    if (isSymlink(f)) f.delete();
                    try (OutputStream o = new FileOutputStream(f)) {
                        copy(in, o, size);
                    }
                    skip(in, pad(size));
                    Os.chmod(f.getPath(), (mode & 0777) | 0600);
                    break;
                default: // devices, fifos: not representable in app storage
                    skip(in, size + pad(size));
            }
        }
    }

    /** Strip leading "./" and "/", reject paths that leave the destination. */
    private static String clean(String name) {
        while (name.startsWith("./")) name = name.substring(2);
        while (name.startsWith("/")) name = name.substring(1);
        if (name.equals(".")) name = "";
        while (name.endsWith("/")) name = name.substring(0, name.length() - 1);
        for (String part : name.split("/")) if (part.equals("..")) return null;
        return name;
    }

    private static String[] parsePax(byte[] d) {
        String[] r = new String[2];
        int i = 0;
        while (i < d.length) {
            int sp = i;
            while (sp < d.length && d[sp] != ' ') sp++;
            if (sp >= d.length) break;
            int len;
            try {
                len = Integer.parseInt(new String(d, i, sp - i, StandardCharsets.US_ASCII));
            } catch (NumberFormatException e) {
                break;
            }
            if (len <= 0 || i + len > d.length) break;
            String rec = new String(d, sp + 1, i + len - sp - 2, StandardCharsets.UTF_8);
            int eq = rec.indexOf('=');
            if (eq > 0) {
                String k = rec.substring(0, eq), v = rec.substring(eq + 1);
                if (k.equals("path")) r[0] = v;
                else if (k.equals("linkpath")) r[1] = v;
            }
            i += len;
        }
        return r;
    }

    private static long pad(long size) {
        return (512 - size % 512) % 512;
    }

    private static boolean readFully(InputStream in, byte[] b) throws IOException {
        int off = 0;
        while (off < b.length) {
            int n = in.read(b, off, b.length - off);
            if (n < 0) {
                if (off == 0) return false;
                throw new IOException("truncated tar");
            }
            off += n;
        }
        return true;
    }

    private static void skip(InputStream in, long n) throws IOException {
        while (n > 0) {
            long k = in.skip(n);
            if (k <= 0) {
                if (in.read() < 0) throw new IOException("truncated tar");
                k = 1;
            }
            n -= k;
        }
    }

    private static boolean isZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    private static String cstr(byte[] b, int off, int len) {
        int end = off;
        while (end < off + len && end < b.length && b[end] != 0) end++;
        return new String(b, off, end - off, StandardCharsets.UTF_8);
    }

    private static long number(byte[] b, int off, int len) {
        if ((b[off] & 0x80) != 0) { // base-256
            long v = b[off] & 0x7f;
            for (int i = 1; i < len; i++) v = (v << 8) | (b[off + i] & 0xff);
            return v;
        }
        long v = 0;
        for (int i = off; i < off + len; i++) {
            int c = b[i];
            if (c == 0 || c == ' ') {
                if (v != 0) break;
                continue;
            }
            if (c < '0' || c > '7') break;
            v = v * 8 + (c - '0');
        }
        return v;
    }
}
