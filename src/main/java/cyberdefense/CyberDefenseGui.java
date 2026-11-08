package cyberdefense;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Path;

/** Optional desktop interface for the same analysis rules used by Main. */
public final class CyberDefenseGui {
    private final JFrame frame = new JFrame("Cyber Defense Analyzer");
    private final JTextField inputField = new JTextField("data/sample_events.csv", 32);
    private final JTextArea reportArea = new JTextArea();
    private final JLabel status = new JLabel("Ready — choose a CSV file and analyze it.");
    private String currentReport = "";

    private CyberDefenseGui() {
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        JButton browse = new JButton("Browse…");
        JButton analyze = new JButton("Analyze logs");
        JButton save = new JButton("Save report…");
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel("CSV file:")); top.add(inputField); top.add(browse); top.add(analyze); top.add(save);
        top.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        reportArea.setEditable(false);
        reportArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        reportArea.setRows(24);
        reportArea.setColumns(90);
        reportArea.setText("Choose a CSV file or use data/sample_events.csv, then click Analyze logs.");
        JPanel content = new JPanel(new BorderLayout(0, 6));
        content.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));
        content.add(top, BorderLayout.NORTH);
        content.add(new JScrollPane(reportArea), BorderLayout.CENTER);
        status.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
        content.add(status, BorderLayout.SOUTH);
        frame.setContentPane(content);

        browse.addActionListener(e -> chooseInput());
        analyze.addActionListener(e -> analyze());
        save.addActionListener(e -> saveReport());
        frame.pack();
        frame.setMinimumSize(new Dimension(760, 420));
        frame.setLocationRelativeTo(null);
        frame.validate();
        frame.setVisible(true);
    }

    private void chooseInput() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) inputField.setText(chooser.getSelectedFile().getPath());
    }

    private void analyze() {
        try {
            var loaded = LogReader.read(Path.of(inputField.getText().trim()));
            var alerts = new ThreatAnalyzer().analyze(loaded.events());
            currentReport = new SecurityReport().render(loaded.events(), alerts, loaded.errors(), null, null, null);
            reportArea.setText(currentReport);
            reportArea.setCaretPosition(0);
            status.setText("Analysis complete — " + loaded.events().size() + " valid events, " + alerts.size() + " alerts, " + loaded.errors().size() + " invalid rows.");
        } catch (IOException | RuntimeException ex) {
            status.setText("Analysis failed.");
            JOptionPane.showMessageDialog(frame, "Could not analyze the selected file:\n" + ex.getMessage(), "Analysis error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveReport() {
        if (currentReport.isEmpty()) { JOptionPane.showMessageDialog(frame, "Analyze a log file before saving a report."); return; }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("security_report.txt"));
        if (chooser.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            try {
                new SecurityReport().save(chooser.getSelectedFile().toPath(), currentReport);
                JOptionPane.showMessageDialog(frame, "Report saved.");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(frame, "Could not save report:\n" + ex.getMessage(), "Save error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(CyberDefenseGui::new);
    }
}
