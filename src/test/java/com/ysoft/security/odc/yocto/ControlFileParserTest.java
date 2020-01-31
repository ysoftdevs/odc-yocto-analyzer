package com.ysoft.security.odc.yocto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ControlFileParserTest {

    @Test
    public void parseControlFile() throws IOException {
        try(final InputStream in = getClass().getResourceAsStream("/example.control")) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final byte[] buff = new byte[1024];
            int len;
            while((len = in.read(buff)) != -1){
                baos.write(buff, 0, len);
            }
            final String s = baos.toString("utf-8");
            final Map<Key, String> res = ControlFileParser.parseControlFile(s);
            // single-line
            assertEquals(res.get(new Key("Package")), "augeas-lenses");
            // case sensitivity
            assertEquals(res.get(new Key("packAge")), "augeas-lenses");
            // missint
            assertEquals(res.get(new Key("hackage")), null);
            // multiline
            assertEquals(res.get(new Key("Description")), "Augeas configuration API\n" + "Augeas configuration API.");
            // last line
            assertEquals(res.get(new Key("Source")), "http://download.augeas.net/augeas-1.4.0.tar.gz file://add-missing-argz-conditional"
                    + ".patch file://sepbuildfix.patch file://0001-Unset-need_charset_alias-when-building-for-musl.patch");
        }
    }


}