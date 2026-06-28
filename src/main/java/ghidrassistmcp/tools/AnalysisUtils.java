package ghidrassistmcp.tools;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyEditor;
import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.ActionTrigger;
import ghidra.framework.options.CustomOption;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import javax.swing.KeyStroke;

final class AnalysisUtils {

    static final String MODE_FULL = "full";
    static final String MODE_CHANGES = "changes";

    private AnalysisUtils() {
    }

    static AutoAnalysisManager getManager(Program program) {
        return AutoAnalysisManager.getAnalysisManager(program);
    }

    static Options getAnalysisOptions(Program program) {
        getManager(program);
        return program.getOptions(Program.ANALYSIS_PROPERTIES);
    }

    static Options getProgramInfoOptions(Program program) {
        return program.getOptions(Program.PROGRAM_INFO);
    }

    static String setAskToAnalyze(Program program, boolean askToAnalyze) {
        Options options = getProgramInfoOptions(program);
        boolean current = options.getBoolean(Program.ASK_TO_ANALYZE_OPTION_NAME, true);
        if (current == askToAnalyze) {
            return "Should Ask To Analyze already " + askToAnalyze;
        }

        int txId = program.startTransaction("Set Ask To Analyze");
        boolean committed = false;
        try {
            options.setBoolean(Program.ASK_TO_ANALYZE_OPTION_NAME, askToAnalyze);
            committed = true;
            return "Set Should Ask To Analyze to " + askToAnalyze;
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    static boolean isAnalyzed(Program program) {
        Options options = getProgramInfoOptions(program);
        return options.getBoolean(Program.ANALYZED_OPTION_NAME, false);
    }

    static boolean shouldAskToAnalyze(Program program) {
        Options options = getProgramInfoOptions(program);
        return options.getBoolean(Program.ASK_TO_ANALYZE_OPTION_NAME, true);
    }

    static List<OptionSnapshot> listAnalysisOptions(Program program) {
        Options options = getAnalysisOptions(program);
        List<OptionSnapshot> snapshots = new ArrayList<>();
        for (String name : options.getOptionNames()) {
            OptionType type = options.getType(name);
            String value = safeValue(options, name);
            String defaultValue = safeDefaultValue(options, name);
            String description = safeDescription(options, name);
            boolean isDefault = value.equals(defaultValue);
            snapshots.add(new OptionSnapshot(name, type.toString(), value, defaultValue,
                description, isDefault));
        }
        snapshots.sort(Comparator.comparing(o -> o.name, String.CASE_INSENSITIVE_ORDER));
        return snapshots;
    }

    static List<String> applyAnalysisOptions(Program program, Map<String, Object> optionOverrides) {
        List<String> errors = new ArrayList<>();
        if (optionOverrides == null || optionOverrides.isEmpty()) {
            return errors;
        }

        Options options = getAnalysisOptions(program);
        int txId = program.startTransaction("Set Analysis Options");
        boolean committed = false;
        try {
            for (Map.Entry<String, Object> entry : optionOverrides.entrySet()) {
                String error = setAnalysisOption(options, entry.getKey(), entry.getValue());
                if (!error.isEmpty()) {
                    errors.add(error);
                }
            }
            committed = errors.isEmpty();
            return errors;
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    static List<String> resetAnalysisOptions(Program program, List<String> optionNames) {
        List<String> errors = new ArrayList<>();
        Options options = getAnalysisOptions(program);

        int txId = program.startTransaction("Reset Analysis Options");
        boolean committed = false;
        try {
            if (optionNames == null || optionNames.isEmpty()) {
                for (String name : options.getOptionNames()) {
                    options.restoreDefaultValue(name);
                }
            } else {
                for (String name : optionNames) {
                    if (!options.contains(name)) {
                        errors.add("Analysis option not found: " + name);
                        continue;
                    }
                    options.restoreDefaultValue(name);
                }
            }
            committed = errors.isEmpty();
            return errors;
        } finally {
            program.endTransaction(txId, committed);
        }
    }

    static String runAnalysis(Program program, String mode, AddressSetView restrictSet,
                              Map<String, Object> optionOverrides, TaskMonitor monitor) {
        TaskMonitor activeMonitor = monitor != null ? monitor : TaskMonitor.DUMMY;
        activeMonitor.setMessage("Applying analysis options");
        List<String> optionErrors = applyAnalysisOptions(program, optionOverrides);
        if (!optionErrors.isEmpty()) {
            return "Analysis option errors:\n- " + String.join("\n- ", optionErrors);
        }

        String normalizedMode = normalizeMode(mode);
        AutoAnalysisManager manager = getManager(program);
        long start = System.currentTimeMillis();

        activeMonitor.setMessage("Starting analysis");
        if (MODE_CHANGES.equals(normalizedMode)) {
            if (restrictSet != null && !restrictSet.isEmpty()) {
                return "mode 'changes' cannot be restricted to an address range. Use mode 'full'.";
            }
            manager.startAnalysis(activeMonitor);
        } else {
            manager.reAnalyzeAll(restrictSet);
            manager.startAnalysis(activeMonitor);
        }

        activeMonitor.setMessage("Waiting for analysis");
        manager.waitForAnalysis(null, activeMonitor);
        long elapsed = System.currentTimeMillis() - start;

        StringBuilder sb = new StringBuilder();
        sb.append("Analysis completed for ").append(program.getName()).append("\n");
        sb.append("  Mode: ").append(normalizedMode).append("\n");
        if (restrictSet != null && !restrictSet.isEmpty()) {
            sb.append("  Restricted Range: ").append(restrictSet.getMinAddress())
              .append(" - ").append(restrictSet.getMaxAddress()).append("\n");
        } else {
            sb.append("  Restricted Range: none\n");
        }
        sb.append("  Option Overrides: ")
          .append(optionOverrides != null ? optionOverrides.size() : 0).append("\n");
        sb.append("  Duration: ").append(elapsed).append("ms\n");
        sb.append("  Analyzed Flag: ").append(isAnalyzed(program)).append("\n");
        sb.append("  Should Ask To Analyze: ").append(shouldAskToAnalyze(program));
        return sb.toString();
    }

    static String normalizeMode(String mode) {
        if (mode == null || mode.isBlank()) {
            return MODE_FULL;
        }
        String normalized = mode.trim().toLowerCase();
        if (MODE_FULL.equals(normalized) || MODE_CHANGES.equals(normalized)) {
            return normalized;
        }
        throw new IllegalArgumentException("Invalid analysis mode: " + mode + ". Use 'full' or 'changes'.");
    }

    static AddressSet parseRange(Program program, String startAddress, String endAddress) {
        if ((startAddress == null || startAddress.isBlank()) &&
            (endAddress == null || endAddress.isBlank())) {
            return null;
        }
        if (startAddress == null || startAddress.isBlank() ||
            endAddress == null || endAddress.isBlank()) {
            throw new IllegalArgumentException("Both start_address and end_address are required for range analysis.");
        }

        Address start = program.getAddressFactory().getAddress(startAddress);
        Address end = program.getAddressFactory().getAddress(endAddress);
        if (start == null || end == null) {
            throw new IllegalArgumentException("Invalid address range: " + startAddress + " - " + endAddress);
        }
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException("start_address must be <= end_address.");
        }
        return new AddressSet(start, end);
    }

    static Map<String, Object> objectMap(Object value) {
        if (!(value instanceof Map<?, ?> rawMap)) {
            return null;
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
            if (entry.getKey() != null) {
                result.put(entry.getKey().toString(), entry.getValue());
            }
        }
        return result;
    }

    static List<String> stringList(Object value) {
        if (!(value instanceof List<?> rawList)) {
            return null;
        }
        List<String> result = new ArrayList<>();
        for (Object item : rawList) {
            if (item != null) {
                result.add(item.toString());
            }
        }
        return result;
    }

    private static String setAnalysisOption(Options options, String optionName, Object optionValue) {
        if (optionValue == null) {
            return optionName + " cannot be set to null.";
        }
        if (!options.contains(optionName)) {
            return optionName + " could not be found for this program.";
        }

        OptionType optionType = options.getType(optionName);
        try {
            switch (optionType) {
                case INT_TYPE:
                    options.setInt(optionName, asNumber(optionValue).intValue());
                    break;
                case LONG_TYPE:
                    options.setLong(optionName, asNumber(optionValue).longValue());
                    break;
                case STRING_TYPE:
                    options.setString(optionName, optionValue.toString());
                    break;
                case DOUBLE_TYPE:
                    options.setDouble(optionName, asNumber(optionValue).doubleValue());
                    break;
                case FLOAT_TYPE:
                    options.setFloat(optionName, asNumber(optionValue).floatValue());
                    break;
                case BOOLEAN_TYPE:
                    options.setBoolean(optionName, asBoolean(optionValue));
                    break;
                case ENUM_TYPE:
                    setEnum(options, optionName, optionValue.toString());
                    break;
                case KEYSTROKE_TYPE:
                    options.setKeyStroke(optionName,
                        (KeyStroke) convertOptionValue(options, optionName, optionType, optionValue));
                    break;
                case FONT_TYPE:
                    options.setFont(optionName,
                        (Font) convertOptionValue(options, optionName, optionType, optionValue));
                    break;
                case DATE_TYPE:
                    options.setDate(optionName,
                        (Date) convertOptionValue(options, optionName, optionType, optionValue));
                    break;
                case BYTE_ARRAY_TYPE:
                    options.setByteArray(optionName, asByteArray(options, optionName, optionValue));
                    break;
                case COLOR_TYPE:
                    options.setColor(optionName,
                        (Color) convertOptionValue(options, optionName, optionType, optionValue));
                    break;
                case FILE_TYPE:
                    options.setFile(optionName,
                        (File) convertOptionValue(options, optionName, optionType, optionValue));
                    break;
                case ACTION_TRIGGER:
                    options.setActionTrigger(optionName,
                        (ActionTrigger) convertOptionValue(options, optionName, optionType, optionValue));
                    break;
                case CUSTOM_TYPE:
                    Object customValue = convertOptionValue(options, optionName, optionType, optionValue);
                    if (!(customValue instanceof CustomOption customOption)) {
                        return "Custom option " + optionName +
                            " could not be converted. This option requires a registered property editor " +
                            "or a Ghidra CustomOption string representation.";
                    }
                    options.setCustomOption(optionName, customOption);
                    break;
                case NO_TYPE:
                default:
                    return "Unsupported analysis option type for " + optionName + ": " + optionType + ".";
            }
            return "";
        } catch (NumberFormatException e) {
            return "Could not convert '" + optionValue + "' for " + optionName + " to " + optionType + ".";
        } catch (IllegalArgumentException e) {
            return "Error changing option '" + optionName + "': " + e.getMessage();
        }
    }

    private static Object convertOptionValue(Options options, String optionName, OptionType optionType,
                                             Object optionValue) {
        if (optionType.isCompatible(optionValue)) {
            return optionValue;
        }

        String text = optionValue.toString();
        PropertyEditor editor = options.getPropertyEditor(optionName);
        if (editor == null) {
            editor = options.getRegisteredPropertyEditor(optionName);
        }
        if (editor != null) {
            try {
                editor.setAsText(text);
                Object editorValue = editor.getValue();
                if (optionType.isCompatible(editorValue)) {
                    return editorValue;
                }
            } catch (IllegalArgumentException e) {
                Msg.debug(AnalysisUtils.class, "Property editor could not parse option: " + optionName, e);
            }
        }

        Object converted = optionType.convertStringToObject(text);
        if (!optionType.isCompatible(converted)) {
            throw new IllegalArgumentException("Converted value for " + optionName +
                " is not compatible with " + optionType + ".");
        }
        return converted;
    }

    private static byte[] asByteArray(Options options, String optionName, Object optionValue) {
        if (optionValue instanceof byte[] bytes) {
            return bytes;
        }
        if (optionValue instanceof List<?> list) {
            byte[] bytes = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                if (!(item instanceof Number number)) {
                    throw new IllegalArgumentException("Byte array list values must be numbers.");
                }
                bytes[i] = (byte) number.intValue();
            }
            return bytes;
        }
        return (byte[]) convertOptionValue(options, optionName, OptionType.BYTE_ARRAY_TYPE, optionValue);
    }

    private static Number asNumber(Object value) {
        if (value instanceof Number number) {
            return number;
        }
        return Double.valueOf(value.toString());
    }

    private static boolean asBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        String text = value.toString().trim().toLowerCase();
        if ("true".equals(text)) {
            return true;
        }
        if ("false".equals(text)) {
            return false;
        }
        throw new IllegalArgumentException("Boolean value must be true or false.");
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static void setEnum(Options options, String optionName, String optionValue) {
        Enum current = options.getEnum(optionName, null);
        if (current == null) {
            throw new IllegalArgumentException("No existing enum value is available.");
        }

        Class enumClass = current.getDeclaringClass();
        for (Object constant : enumClass.getEnumConstants()) {
            Enum enumValue = (Enum) constant;
            if (enumValue.name().equals(optionValue) || enumValue.toString().equals(optionValue)) {
                options.setEnum(optionName, enumValue);
                return;
            }
        }
        throw new IllegalArgumentException("Unknown enum value: " + optionValue);
    }

    private static String safeValue(Options options, String name) {
        try {
            String value = options.getValueAsString(name);
            return value != null ? value : "";
        } catch (Exception e) {
            Msg.debug(AnalysisUtils.class, "Failed to read option value: " + name, e);
            return "";
        }
    }

    private static String safeDefaultValue(Options options, String name) {
        try {
            String value = options.getDefaultValueAsString(name);
            return value != null ? value : "";
        } catch (Exception e) {
            Object defaultValue = options.getDefaultValue(name);
            return defaultValue != null ? defaultValue.toString() : "";
        }
    }

    private static String safeDescription(Options options, String name) {
        try {
            String description = options.getDescription(name);
            return description != null ? description : "";
        } catch (Exception e) {
            Msg.debug(AnalysisUtils.class, "Failed to read option description: " + name, e);
            return "";
        }
    }

    static class OptionSnapshot {
        final String name;
        final String type;
        final String value;
        final String defaultValue;
        final String description;
        final boolean isDefault;

        OptionSnapshot(String name, String type, String value, String defaultValue,
                       String description, boolean isDefault) {
            this.name = name;
            this.type = type;
            this.value = value;
            this.defaultValue = defaultValue;
            this.description = description;
            this.isDefault = isDefault;
        }
    }
}
