package org.igniterealtime.openfire.plugins.skypeintegration;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.user.UserNameManager;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class SkypeIntegrationPlugin implements Plugin {

    private static final Logger Log = LoggerFactory.getLogger(SkypeIntegrationPlugin.class);
    private String skypeDomain;

    private SkypeUsernameProvider provider = new SkypeUsernameProvider();

    public void initializePlugin(PluginManager pluginManager, File file) {
        skypeDomain = JiveGlobals.getProperty("skypeintegration.ldapdomain", "example.com");
        System.setProperty("org.jitsi.jicofo.DISABLE_AUTO_OWNER",
                            JiveGlobals.getProperty("skypeintegration.disableautoowner", "false") );
        UserNameManager.addUserNameProvider(skypeDomain, provider);
        provider.SetupCaches();
    }

    public void destroyPlugin() {
        UserNameManager.removeUserNameProvider(skypeDomain);
        provider.DestroyCaches();
    }
}
