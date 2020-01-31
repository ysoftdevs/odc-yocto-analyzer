package com.ysoft.security.odc.yocto;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.owasp.dependencycheck.analyzer.AbstractFileTypeAnalyzer;
import org.owasp.dependencycheck.utils.InvalidSettingException;
import org.owasp.dependencycheck.utils.Settings;

import static com.ysoft.security.odc.yocto.ControlFileParser.parseControlFile;

abstract class AbstractYoctoAnalyzer extends AbstractFileTypeAnalyzer {

    public static final String YOCTO_ANALYZER_KEY = "com.ysoft.yocto.enabled";
    public static final String YOCTO_ANALYZER_EXPERIMENTAL_DEBIAN_KEY = "com.ysoft.yocto.experimental.debian.enabled";
    public static final String IPK_SOURCE = "ipk";

    protected FileFilter getFileFilter() {
        return f -> {
            final String name = f.getName().toLowerCase();
            return name.endsWith(".ipk") || (isExperimentalDebEnabled() && name.endsWith(".deb"));
        };
    }

    @Override
    protected String getAnalyzerEnabledSettingKey() {
        return YOCTO_ANALYZER_KEY;
    }

    private void throwChecked(Throwable e) {
        this.throwChecked0(e);
    }

    protected boolean isExperimentalDebEnabled() {
        return getSettings().getBoolean(YOCTO_ANALYZER_EXPERIMENTAL_DEBIAN_KEY, false);
    }

    @SuppressWarnings("unchecked")
    private <T extends RuntimeException> void throwChecked0(Throwable e) {
        throw (T) e;
    }


    // In future, we might want to be more universal: https://blog.philippklaus.de/2011/04/have-a-look-into-an-ipk-file-used-by-the-ipkg-or-opkg-manager

    protected IpkFile parseIpkFile(File ipkFile) throws IOException {
        return new IpkFile(parseIpkManifest(ipkFile));//listIpkFiles(ipkFile));
    }

    private Set<String> listIpkFiles(File ipkFile) throws IOException {
        // TODO: add support for xz, bz etc.
        final Process arProcess = createArExtractionProcess(ipkFile.getAbsolutePath(), "data.tar.gz");
        try{
            final Future<String> arStderrFuture = processStream(arProcess.getErrorStream());
            final Process tarProcess = new ProcessBuilder("tar", "-tz").start();
            try {
                final Future<String> tarStderrFuture = processStream(tarProcess.getErrorStream());
                final Future<Void> copyResult = pipe(arProcess.getInputStream(), tarProcess.getOutputStream());
                final Set<String> fileNames = new HashSet<>();
                try(final BufferedReader reader = new BufferedReader(new InputStreamReader(tarProcess.getInputStream()))){
                    String line;
                    while((line = reader.readLine()) != null){
                        fileNames.add(line);
                    }
                }
                copyResult.get(); // this throws exception if pipe has failed
                final int tarReturnCode = tarProcess.waitFor();
                final int arReturnCode = arProcess.waitFor();
                checkStderr(tarStderrFuture, "tar");
                checkStderr(arStderrFuture, "ar");
                if (tarReturnCode != 0 || arReturnCode != 0) {
                    throw new IOException("Bad return code (tar: " + tarReturnCode + ", ar: " + arReturnCode + ")");
                }
                return fileNames;
            } catch (InterruptedException | ExecutionException e) {
                throw new IOException(e);
            } finally {
                tarProcess.destroyForcibly();
            }
        }finally{
            arProcess.destroyForcibly();
        }
    }

    private IpkManifest parseIpkManifest(File ipkFile) throws IOException {
        final Process arProcess = createArExtractionProcess(ipkFile.getAbsolutePath(), "control.tar.gz");
        try{
            final Future<String> arStderrFuture = processStream(arProcess.getErrorStream());
            final Process tarProcess = new ProcessBuilder("tar", "-xzO", "./control").start();
            try{
                final Future<String> tarStderrFuture = processStream(tarProcess.getErrorStream());
                final Future<Void> copyResult = pipe(arProcess.getInputStream(), tarProcess.getOutputStream());
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int len;
                final byte[] buff = new byte[1024];
                while((len = tarProcess.getInputStream().read(buff)) != -1){
                    baos.write(buff, 0, len);
                }
                copyResult.get(); // this throws exception if pipe has failed
                final int tarReturnCode = tarProcess.waitFor();
                final int arReturnCode = arProcess.waitFor();
                checkStderr(tarStderrFuture, "tar");
                checkStderr(arStderrFuture, "ar");
                if(tarReturnCode != 0 || arReturnCode != 0){
                    throw new IOException("Bad return code (tar: "+tarReturnCode+", ar: "+arReturnCode+")");
                }
                return new IpkManifest(parseControlFile(baos.toString("utf-8")));
            } catch (InterruptedException | ExecutionException e) {
                throw new IOException(e);
            } finally {
                tarProcess.destroyForcibly();
            }
        }finally{
            arProcess.destroyForcibly();
        }
    }

    private Process createArExtractionProcess(String arPath, String file) throws IOException {
        return new ProcessBuilder("ar", "p", "--", arPath, file).start();
    }

    private void checkStderr(Future<String> stderrFuture, String name) throws ExecutionException, InterruptedException, IOException {
        final String result = stderrFuture.get();
        if(!result.equals("")){
            throw new IOException("Process "+name+" has written something to stderr: "+result);
        }
    }

    private Future<String> processStream(InputStream inputStream) {
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            return executor.submit(() -> {
                final InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
                final char[] buff = new char[1024];
                int len;
                final StringBuilder out = new StringBuilder();
                while ((len = reader.read(buff)) != -1){
                    out.append(buff, 0, len);
                }
                return out.toString();
            });
        }finally {
            executor.shutdown();
        }
    }


    protected Future<Void> pipe(InputStream in, OutputStream out){
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        try{
            return executor.submit(() -> {
                int len;
                final byte[] buff = new byte[1024];
                try {
                    while ((len = in.read(buff)) != -1) {
                        out.write(buff, 0, len);
                    }
                    out.close();
                } catch (IOException e){
                    throwChecked(e);
                }
                return null;
            });
        }finally {
            executor.shutdown();
        }
    }

}
