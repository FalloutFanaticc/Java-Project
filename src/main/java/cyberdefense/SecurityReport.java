package cyberdefense;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/** Formats, filters, summarizes, and persists analysis results. */
public final class SecurityReport {
    public String render(List<LogEvent> events, List<ThreatAnalyzer.Alert> alerts, List<String> errors, String typeFilter, String userFilter, ThreatAnalyzer.Severity minSeverity) {
        List<LogEvent> filtered = events.stream().filter(e -> typeFilter == null || e.eventType().equalsIgnoreCase(typeFilter))
                .filter(e -> userFilter == null || e.username().equalsIgnoreCase(userFilter)).toList();
        List<ThreatAnalyzer.Alert> chosen = alerts.stream().filter(a -> minSeverity == null || a.severity().compareTo(minSeverity) >= 0).toList();
        Map<ThreatAnalyzer.Severity, Long> counts = new TreeMap<>();
        for (ThreatAnalyzer.Severity s : ThreatAnalyzer.Severity.values()) counts.put(s, chosen.stream().filter(a -> a.severity() == s).count());
        StringBuilder b = new StringBuilder("CYBER DEFENSE ANALYZER REPORT\n=============================\n");
        b.append("Events loaded: ").append(events.size()).append(" | Events shown: ").append(filtered.size()).append(" | Alerts: ").append(chosen.size()).append('\n');
        b.append("Malformed rows skipped: ").append(errors.size()).append('\n');
        for (var e : counts.entrySet()) b.append("  ").append(e.getKey()).append(": ").append(e.getValue()).append('\n');
        b.append("\nALERTS (prioritized)\n");
        if (chosen.isEmpty()) b.append("No alerts matched the selected filter.\n");
        for (var a : chosen) b.append('[').append(a.severity()).append(" | risk ").append(a.riskScore()).append("] ").append(a.title()).append('\n')
                .append("  Why: ").append(a.explanation()).append('\n').append("  Action: ").append(a.recommendation()).append('\n');
        b.append("\nEVENTS (chronological)\n");
        for (var e : filtered) b.append(e.timestamp()).append(" | ").append(e.username()).append(" | ").append(e.eventType()).append(" | ").append(e.sourceIp()).append('\n');
        if (!errors.isEmpty()) { b.append("\nINPUT WARNINGS\n"); errors.forEach(e -> b.append("  ").append(e).append('\n')); }
        b.append("\nRisk scores are rule-based prioritization aids, not probabilities.\n");
        return b.toString();
    }
    public void save(Path path, String report) throws IOException { if (path.getParent() != null) Files.createDirectories(path.getParent()); Files.writeString(path, report); }
}
