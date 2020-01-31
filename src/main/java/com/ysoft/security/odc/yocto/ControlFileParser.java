package com.ysoft.security.odc.yocto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

class ControlFileLineBuilder{

    private final List<String> lines = new ArrayList<>();
    private final Key key;

    public ControlFileLineBuilder(String line) throws IOException {
        final int pos = line.indexOf(':');
        if(pos == -1){
            throw new IOException("Bad line: expected colon: "+line);
        }
        key = new Key(line.substring(0, pos));
        addLine(line.substring(pos+1));
    }

    private void addLine(String s) {
        lines.add(s.trim());
    }

    public Line build() {
        return new Line(key, lines.stream().collect(Collectors.joining("\n")));
    }

    public void add(String line) {
        addLine(line);
    }
}

class Line{
    private final Key key;
    private final String value;
    public Line(Key key, String value) {
        this.key = key;
        this.value = value;
    }
    public Key getKey() {
        return key;
    }
    public String getValue() {
        return value;
    }
}

class ControlFileParagraphBuilder{

    private ControlFileLineBuilder lineBuilder;

    private Map<Key, String> map = new HashMap<>();

    public void addLine(String line) throws IOException {
        if(line.startsWith(" ") || line.startsWith("\t")){
            if(lineBuilder == null) {
                throw new IOException("Bad control file: paragraph cannot start with whitespace.");
            } else {
                lineBuilder.add(line);
            }
        }else{
            finishCurrentLine();
            lineBuilder = new ControlFileLineBuilder(line);
        }
    }

    private void finishCurrentLine() throws IOException {
        if(lineBuilder != null){
            add(lineBuilder.build());
            lineBuilder = null;
        }
    }

    private void add(Line line) throws IOException {
        if(map.containsKey(line.getKey())){
            throw new IOException("Duplicate key: "+line.getKey());
        }
        map.put(line.getKey(), line.getValue());
    }

    public Map<Key, String> build() throws IOException {
        finishCurrentLine();
        final Map<Key, String> res = Collections.unmodifiableMap(map);
        map = null; // don't allow reuse
        return res;
    }
}

public class ControlFileParser {

    /**
     * Works according specification https://www.debian.org/doc/debian-policy/ch-controlfields.html with some limitations:
     * * parses only one paragraph
     * @param s
     * @return
     */
    public static Map<Key, String> parseControlFile(String s) throws IOException {
        final ControlFileParagraphBuilder builder = new ControlFileParagraphBuilder();
        for(final String line : s.split("\n")){
            builder.addLine(line);
        }
        return builder.build();
    }

}
