package cyberdefense;

import java.time.LocalDateTime;

/** One validated row from the synthetic security event log. */
public record LogEvent(LocalDateTime timestamp, String username, String eventType, String sourceIp, int lineNumber) { }
