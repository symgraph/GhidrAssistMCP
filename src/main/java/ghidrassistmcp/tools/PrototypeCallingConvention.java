package ghidrassistmcp.tools;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.util.exception.InvalidInputException;

/** Calling-convention handling around Ghidra's deliberately limited signature parser. */
final class PrototypeCallingConvention {
    private PrototypeCallingConvention() {}

    static Declaration extract(CompilerSpec compiler, String prototype) throws InvalidInputException {
        int paren = prototype.indexOf('(');
        if (paren < 0) return new Declaration(prototype, null);

        // The final whitespace-delimited token is the function name, not a convention.
        int nameStart = paren;
        while (nameStart > 0 && Character.isWhitespace(prototype.charAt(nameStart - 1))) nameStart--;
        while (nameStart > 0 && !Character.isWhitespace(prototype.charAt(nameStart - 1))) nameStart--;
        String prefix = prototype.substring(0, nameStart);
        Set<String> supported = new LinkedHashSet<>();
        for (PrototypeModel model : compiler.getCallingConventions()) {
            if (model != null && model.getName() != null && !model.getName().isBlank()
                    && !CompilerSpec.isUnknownCallingConvention(model.getName())) {
                supported.add(model.getName());
            }
        }

        String convention = null;
        int start = -1;
        int end = -1;
        for (String name : supported) {
            Matcher matcher = Pattern.compile("(?<!\\S)" + Pattern.quote(name) + "(?!\\S)").matcher(prefix);
            while (matcher.find()) {
                if (convention != null) {
                    throw new InvalidInputException("Multiple calling convention tokens in prototype");
                }
                convention = name;
                start = matcher.start();
                end = matcher.end();
            }
        }
        if (convention == null) return new Declaration(prototype, null);
        return new Declaration(prototype.substring(0, start) + prototype.substring(end), convention);
    }

    static String resolve(CompilerSpec compiler, String current, String explicit)
            throws InvalidInputException {
        if (explicit != null) {
            if (compiler.getCallingConvention(explicit) == null) {
                throw new InvalidInputException("Unsupported calling convention: " + explicit);
            }
            return explicit;
        }
        if (!CompilerSpec.isUnknownCallingConvention(current)
                && compiler.getCallingConvention(current) != null) {
            return current;
        }
        PrototypeModel nativeDefault = compiler.getDefaultCallingConvention();
        String name = nativeDefault == null ? null : nativeDefault.getName();
        if (name == null || name.isBlank() || CompilerSpec.isUnknownCallingConvention(name)
                || compiler.getCallingConvention(name) == null) {
            throw new InvalidInputException("Selected compiler has no valid default calling convention");
        }
        return name;
    }

    record Declaration(String prototype, String callingConvention) {}
}
