package eu.starsong.ghidra.hateoas;

/**
 * Shared helper for the {@code {}}-placeholder link template formatting used by
 * {@link Response} and {@link Links}. Extracted to avoid duplicating the
 * substitution logic in both classes.
 */
final class LinkFormat {

    private LinkFormat() {
    }

    /**
     * Substitute {@code {}} (and {@code {anything}}) placeholders in the
     * template with the given arguments, in order. If no args are supplied the
     * template is returned unchanged.
     */
    static String format(String template, Object... args) {
        if (args == null || args.length == 0) {
            return template;
        }

        StringBuilder result = new StringBuilder();
        int argIndex = 0;
        int i = 0;

        while (i < template.length()) {
            if (i < template.length() - 1 && template.charAt(i) == '{' && template.charAt(i + 1) == '}') {
                if (argIndex < args.length) {
                    result.append(args[argIndex++]);
                } else {
                    result.append("{}");
                }
                i += 2;
            } else if (template.charAt(i) == '{') {
                int end = template.indexOf('}', i);
                if (end != -1 && argIndex < args.length) {
                    result.append(args[argIndex++]);
                    i = end + 1;
                } else {
                    result.append(template.charAt(i));
                    i++;
                }
            } else {
                result.append(template.charAt(i));
                i++;
            }
        }

        return result.toString();
    }
}
