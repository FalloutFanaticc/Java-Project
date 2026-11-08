package cyberdefense;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Applies transparent, deterministic rules to simulated events. */
public final class ThreatAnalyzer {
    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
    public record Alert(Severity severity, int riskScore, String title, String explanation, String recommendation, List<LogEvent> events) { }

    public List<Alert> analyze(List<LogEvent> input) {
        List<LogEvent> events = input.stream().sorted(Comparator.comparing(LogEvent::timestamp)).toList();
        List<Alert> alerts = new ArrayList<>();
        Map<String, List<LogEvent>> failuresByUser = new HashMap<>();
        for (LogEvent e : events) {
            if (e.eventType().equals("LOGIN_FAILURE")) failuresByUser.computeIfAbsent(e.username(), k -> new ArrayList<>()).add(e);
            if (e.eventType().equals("ACCOUNT_LOCKED")) alerts.add(new Alert(Severity.HIGH, 75, "Account locked: " + e.username(),
                    "An account lockout was recorded at " + e.timestamp() + " from " + e.sourceIp() + ".", "Review preceding authentication failures and verify the lockout was expected.", List.of(e)));
            if (e.eventType().equals("FILE_ACCESS_DENIED")) alerts.add(new Alert(Severity.MEDIUM, 35, "Access denied: " + e.username(),
                    "A file access attempt was denied at " + e.timestamp() + " from " + e.sourceIp() + ".", "Confirm the account had a legitimate need for this resource.", List.of(e)));
            if (e.eventType().equals("UNUSUAL_NETWORK_ACTIVITY")) alerts.add(new Alert(Severity.MEDIUM, 40, "Unusual network activity: " + e.username(),
                    "The supplied log labels network activity as unusual at " + e.timestamp() + " from " + e.sourceIp() + ".", "Review the event context and compare it with approved network activity.", List.of(e)));
        }
        for (Map.Entry<String, List<LogEvent>> entry : failuresByUser.entrySet()) {
            List<LogEvent> failures = entry.getValue();
            for (int end = 2; end < failures.size(); end++) {
                LogEvent first = failures.get(end - 2), last = failures.get(end);
                if (Duration.between(first.timestamp(), last.timestamp()).toMinutes() <= 5) {
                    List<LogEvent> window = failures.subList(end - 2, end + 1);
                    alerts.add(new Alert(Severity.HIGH, 80, "Repeated login failures: " + entry.getKey(),
                            window.size() + " failed logins for the same account occurred within five minutes (" + first.timestamp() + " to " + last.timestamp() + ").",
                            "Verify the user through an approved channel, review source activity, and follow the organization's account response procedure.", List.copyOf(window)));
                    break; // one alert per account for this rule
                }
            }
        }
        return alerts.stream().sorted(Comparator.comparing(Alert::severity).reversed().thenComparing(Alert::title)).toList();
    }
}
