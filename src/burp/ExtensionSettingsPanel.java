package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelWithData;

import java.util.Set;

import static burp.api.montoya.ui.settings.SettingsPanelBuilder.settingsPanel;
import static burp.api.montoya.ui.settings.SettingsPanelSetting.booleanSetting;

class ExtensionSettingsPanel {

    static final String VERIFY_GEMINI_KEY = "Verify Gemini API access (sends requests to Google)";
    private static final long MIN_SETTINGS_PANEL_VERSION = 20250600000000000L;
    private static volatile SettingsPanelWithData panel = null;

    static boolean isPanelAvailable() {
        return panel != null;
    }

    static void register(MontoyaApi api) {
        if (api.burpSuite().version().buildNumber() < MIN_SETTINGS_PANEL_VERSION) {
            return;
        }

        try {
            panel = settingsPanel()
                    .withTitle("Google API Key Scan")
                    .withDescription(
                            "When enabled, detected API keys a" +
                                    "re checked against Google's Gemini API " +
                            "endpoints to confirm access. This upgrades findings from Information to " +
                            "Medium/High severity.")
                    .withSetting(booleanSetting(VERIFY_GEMINI_KEY, false))
                    .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                    .withKeywords(Set.of("activescan", "active", "scan", "google", "api", "key", "gemini"))
                    .build();

            api.userInterface().registerSettingsPanel(panel);
        } catch (Exception e) {
            Utilities.err("Could not register settings panel: " + e.getMessage());
        }
    }

    static boolean getVerifyGeminiAccess() {
        return panel != null && panel.getBoolean(VERIFY_GEMINI_KEY);
    }
}