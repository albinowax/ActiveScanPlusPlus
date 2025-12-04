package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;

import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, BurpExtension {
    private static final String name = "ActiveScan++";
    private static final String version = "2.0.8";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    @Override
    public void initialize(MontoyaApi api) {
        Utilities.montoyaApi = api;
        if (!Utilities.montoyaApi.burpSuite().version().edition().equals(BurpSuiteEdition.ENTERPRISE_EDITION)) {
            BulkUtilities.registerContextMenu();
        }
        // api.http().registerHttpHandler(new Tester());
        // api.userInterface().registerContextMenuItemsProvider(new OfferHostnameOverride());
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks, new HashMap<>(), name);
        Utilities.callbacks.setExtensionName(name);
        Utilities.callbacks.registerExtensionStateListener(this);

        Utilities.callbacks.registerScannerCheck(new PerHostScans("Per host scans"));
        Utilities.callbacks.registerScannerCheck(new PerRequestScans("Per request scans"));
        Utilities.callbacks.registerScannerCheck(new CodeExec("Code Exec"));
        Utilities.callbacks.registerScannerCheck(new EdgeSideInclude("Edge Side Include"));
        Utilities.callbacks.registerScannerCheck(new JetLeak("JetLeak"));
        Utilities.callbacks.registerScannerCheck(new SimpleFuzz("Simple Fuzz"));
        Utilities.callbacks.registerScannerCheck(new SolrScan("Solr Scan"));
        Utilities.callbacks.registerScannerCheck(new Struts201712611Scan("Struts 2017-12611 Scan"));
        Utilities.callbacks.registerScannerCheck(new SuspectTransform("Suspect Transform"));
        Utilities.callbacks.registerScannerCheck(new XMLScan("XML security"));
        new KitchenSink("Launch all scans");

        new BulkScanLauncher(BulkScan.scans);

        Utilities.out("Loaded " + name + " v" + version);
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
    }

}

