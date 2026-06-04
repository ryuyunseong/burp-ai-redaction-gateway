package com.ryuyunseong.burpai.redactiongateway;

final class JsonStrings {
    private JsonStrings() {
    }

    static String quote(String value) {
        if (value == null) {
            return "null";
        }

        StringBuilder output = new StringBuilder(value.length() + 2);
        output.append('"');
        for (int index = 0; index < value.length(); index += 1) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    output.append("\\\"");
                    break;
                case '\\':
                    output.append("\\\\");
                    break;
                case '\b':
                    output.append("\\b");
                    break;
                case '\f':
                    output.append("\\f");
                    break;
                case '\n':
                    output.append("\\n");
                    break;
                case '\r':
                    output.append("\\r");
                    break;
                case '\t':
                    output.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        output.append(String.format("\\u%04x", (int) character));
                    } else {
                        output.append(character);
                    }
                    break;
            }
        }
        output.append('"');
        return output.toString();
    }
}
