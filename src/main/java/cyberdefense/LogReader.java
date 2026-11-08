package cyberdefense;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/** Reads and validates the contest's four-column CSV format. */
public final class LogReader {
    public record Result(List<LogEvent> events, List<String> errors) { }
    private LogReader() { }

    public static Result read(Path path) throws IOException {
        List<LogEvent> events = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        List<String> lines = Files.readAllLines(path);
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) continue;
            if (i == 0 && line.toLowerCase().startsWith("timestamp,")) continue;
            try {
                List<String> fields = parseCsv(line);
                if (fields.size() != 4) throw new IllegalArgumentException("expected 4 CSV columns");
                LocalDateTime timestamp = LocalDateTime.parse(fields.get(0).trim());
                String user = fields.get(1).trim(), type = fields.get(2).trim().toUpperCase(), ip = fields.get(3).trim();
                if (user.isEmpty() || type.isEmpty() || ip.isEmpty()) throw new IllegalArgumentException("username, event_type, and source_ip must not be empty");
                events.add(new LogEvent(timestamp, user, type, ip, i + 1));
            } catch (IllegalArgumentException e) {
                errors.add("Line " + (i + 1) + ": " + e.getMessage());
            }
        }
        return new Result(events, errors);
    }

    // Supports quoted fields and escaped double quotes; this dataset needs no external CSV library.
    private static List<String> parseCsv(String line) {
        List<String> out = new ArrayList<>(); StringBuilder field = new StringBuilder(); boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') { field.append('"'); i++; }
                else quoted = !quoted;
            } else if (c == ',' && !quoted) { out.add(field.toString()); field.setLength(0); }
            else field.append(c);
        }
        if (quoted) throw new IllegalArgumentException("unterminated quoted field");
        out.add(field.toString()); return out;
    }
}
