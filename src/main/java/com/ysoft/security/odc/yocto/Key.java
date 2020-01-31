package com.ysoft.security.odc.yocto;

public class Key{
    private final String key;
    private final String canonicalKey;

    public Key(String key) {
        this.key = key;
        this.canonicalKey = key.toLowerCase();
    }

    public String getKey() {
        return key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        Key key = (Key) o;

        return canonicalKey.equals(key.canonicalKey);
    }

    @Override
    public int hashCode() {
        return canonicalKey.hashCode();
    }

    @Override
    public String toString() {
        return "Key(" + key + ")";
    }

}
