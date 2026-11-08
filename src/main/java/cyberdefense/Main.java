package cyberdefense;

import java.io.IOException;
import java.nio.file.Path;

public final class Main {
    private Main() { }
    public static void main(String[] args) {
        Path input = Path.of(args.length > 0 ? args[0] : "data/sample_events.csv");
        Path output = Path.of(args.length > 1 ? args[1] : "reports/security_report.txt");
        String type = option(args, "--type"), user = option(args, "--user"), severityText = option(args, "--min-severity");
        ThreatAnalyzer.Severity severity = null;
        if (severityText != null) try { severity = ThreatAnalyzer.Severity.valueOf(severityText.toUpperCase()); }
        catch (IllegalArgumentException e) { System.err.println("Invalid severity. Use LOW, MEDIUM, HIGH, or CRITICAL."); System.exit(2); }
        try {
            LogReader.Result loaded = LogReader.read(input);
            var alerts = new ThreatAnalyzer().analyze(loaded.events());
            String report = new SecurityReport().render(loaded.events(), alerts, loaded.errors(), type, user, severity);
            System.out.print(report);
            new SecurityReport().save(output, report);
            System.out.println("\nReport saved to " + output);
        } catch (IOException e) { System.err.println("Cannot read or write file: " + e.getMessage()); System.exit(1); }
    }
    private static String option(String[] args, String key) {
        for (int i = 2; i < args.length; i++) if (args[i].equalsIgnoreCase(key)) {
            if (i + 1 >= args.length) { System.err.println("Missing value for " + key); System.exit(2); }
            return args[i + 1];
        }
        return null;
    }
}
