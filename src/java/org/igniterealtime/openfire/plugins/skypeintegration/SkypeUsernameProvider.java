package org.igniterealtime.openfire.plugins.skypeintegration;

import org.jivesoftware.openfire.ldap.LdapManager;
import org.jivesoftware.openfire.user.UserNameProvider;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.Base64;
import org.jivesoftware.util.cache.Cache;
import org.jivesoftware.util.cache.CacheFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.Serializable;
import java.util.*;

import static org.jivesoftware.openfire.ldap.LdapManager.getRelativeDNFromResult;

public class SkypeUsernameProvider implements UserNameProvider {

    private static final Logger Log = LoggerFactory.getLogger(SkypeUsernameProvider.class);

    private String displayNameSuffix;
    private String usernamePrefix;
    private String ldapProperty;

    private LdapManager ldapManager;

    private Cache<String, SkypeUsernameProvider.DNCacheEntry> userDNCache = null;
    private Cache<String, String> ldapNameCache = null;

    public SkypeUsernameProvider() {
        usernamePrefix = "sip:";
        ldapProperty = "msRTCSIP-PrimaryUserAddress";
        displayNameSuffix = " [Skype]";

        ldapManager = LdapManager.getInstance();


    }

    public void SetupCaches() {
        userDNCache = CacheFactory.createCache("SkypeUserDN");
        ldapNameCache = CacheFactory.createCache("SkypeDisplayName");
    }

    public void DestroyCaches() {
        CacheFactory.destroyCache("SkypeUserDN");
        CacheFactory.destroyCache("SkypeDisplayName");
    }

    /**
     * Returns the name of the entity specified by the following JID.
     *
     * @param entity JID of the entity to return its name.
     * @return the name of the entity specified by the following JID.
     */
    public String getUserName( JID entity ) {
        String username = entity.toBareJID();
        if ( ldapNameCache != null )
        {
            // Return a cache entry if one exists.
            final String displayName = ldapNameCache.get( username );
            if ( displayName != null )
            {
                return displayName;
            }
        }

        // No cache entry. Query for the value, and add that to the cache.
        try
        {
            final Map<String, String> ldapAttrib = getLdapAttributes( username );
            String displayName = ldapAttrib.get("displayName");
            if (displayName != null) {
                displayName = displayName + displayNameSuffix;
                if (ldapNameCache != null) {
                    ldapNameCache.put(username, displayName);
                }
                return displayName;
            }
        }
        catch ( Exception ex )
        {
            Log.debug( "An exception occurred while trying to get the display name for {}", username, ex );
        }

        return username;
    }

    private Map<String, String> getLdapAttributes(String username) {
        Map<String, String> map = new HashMap<>();
        DirContext ctx = null;
        try {
            Rdn[] userRDN = findSkypeUserRDN(username);

            ctx = ldapManager.getContext(getSkypeUsersBaseDN(username));
            String[] attributes = {"sAMAccountName", "displayName"};
            Attributes attrs = ctx.getAttributes(LdapManager.escapeForJNDI(userRDN), attributes);

            for (String attribute : attributes) {
                javax.naming.directory.Attribute attr = attrs.get(attribute);
                String value;
                if (attr == null) {
                    Log.debug("SkypeUsernameProvider: No ldap value found for attribute '" + attribute + "'");
                    value = "";
                }
                else {
                    Object ob = attrs.get(attribute).get();
                    Log.debug("SkypeUsernameProvider: Found attribute "+attribute+" of type: "+ob.getClass());
                    if(ob instanceof String) {
                        value = (String)ob;
                    } else {
                        value = Base64.encodeBytes((byte[])ob);
                    }
                }
                Log.debug("SkypeUsernameProvider: Ldap attribute '" + attribute + "'=>'" + value + "'");
                map.put(attribute, value);
            }
            return map;
        }
        catch (Exception e) {
            Log.error(e.getMessage(), e);
            return Collections.emptyMap();
        }
        finally {
            try {
                if (ctx != null) {
                    ctx.close();
                }
            }
            catch (Exception e) {
                // Ignore.
            }
        }
    }

    public LdapName getSkypeUsersBaseDN( String username )
    {
        if ( userDNCache != null )
        {
            // Return a cache entry if one exists.
            final SkypeUsernameProvider.DNCacheEntry dnCacheEntry = userDNCache.get( username );
            if ( dnCacheEntry != null )
            {
                return dnCacheEntry.getBaseDN();
            }
        }

        // No cache entry. Query for the value, and add that to the cache.
        try
        {
            final Rdn[] userRDN = findSkypeUserRDN( username, ldapManager.getBaseDN() );
            if ( userDNCache != null )
            {
                userDNCache.put( username, new SkypeUsernameProvider.DNCacheEntry( userRDN, ldapManager.getBaseDN() ) );
            }
            return ldapManager.getBaseDN();
        }
        catch ( Exception e )
        {
            try
            {
                if ( ldapManager.getAlternateBaseDN() != null )
                {
                    final Rdn[] userRDN = findSkypeUserRDN( username, ldapManager.getAlternateBaseDN() );
                    if ( userDNCache != null )
                    {
                        userDNCache.put( username, new SkypeUsernameProvider.DNCacheEntry( userRDN, ldapManager.getAlternateBaseDN() ) );
                    }
                    return ldapManager.getAlternateBaseDN();
                }
            }
            catch ( Exception ex )
            {
                Log.debug( "An exception occurred while trying to get the user baseDn for {}", username, ex );
            }
        }

        return null;
    }

    /**
     * Username should be bare JID
     */
    private Rdn[] findSkypeUserRDN( String username ) throws Exception
    {
        if ( userDNCache != null )
        {
            // Return a cache entry if one exists.
            final SkypeUsernameProvider.DNCacheEntry dnCacheEntry = userDNCache.get( username );
            if ( dnCacheEntry != null )
            {
                return dnCacheEntry.getUserRDN();
            }
        }

        // No cache entry. Query for the value, and add that to the cache.
        try
        {
            final Rdn[] userRDN = findSkypeUserRDN( username, ldapManager.getBaseDN() );
            if ( userDNCache != null )
            {
                userDNCache.put( username, new SkypeUsernameProvider.DNCacheEntry( userRDN, ldapManager.getBaseDN() ));
            }
            return userRDN;
        }
        catch ( Exception e )
        {
            if ( ldapManager.getAlternateBaseDN() != null )
            {
                final Rdn[] userRDN = findSkypeUserRDN( username, ldapManager.getAlternateBaseDN() );
                if ( userDNCache != null )
                {
                    userDNCache.put( username, new SkypeUsernameProvider.DNCacheEntry( userRDN, ldapManager.getAlternateBaseDN() ) );
                }
                return userRDN;
            }
            else
            {
                throw e;
            }
        }
    }

    public Rdn[] findSkypeUserRDN(String username, LdapName baseDN) throws Exception {
        //Support for usernameSuffix
        username = usernamePrefix + username;
        Log.debug("Trying to find a Skype user's RDN based on their SIP address: '{}'. Field: '{}', Base DN: '{}' ...", username, ldapProperty, baseDN);
        DirContext ctx = null;
        try {
            ctx = ldapManager.getContext(baseDN);
            Log.debug("Starting LDAP search for Skype SIP '{}'...", username);

            // Search for the dn based on the SIP address.
            SearchControls constraints = new SearchControls();
            constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
            constraints.setReturningAttributes(new String[] { ldapProperty });

            // NOTE: this assumes that the username has already been JID-unescaped
            StringBuilder filter = new StringBuilder();
            filter.append('(').append(ldapProperty).append("={0})");
            NamingEnumeration<SearchResult> answer = ctx.search("", filter.toString(),
                    new String[] {username},
                    constraints);

            Log.debug("... search finished for Skype SIP '{}'.", username);

            if (answer == null || !answer.hasMoreElements()) {
                Log.debug("User DN based on Skype SIP '{}' not found.", username);
                throw new UserNotFoundException("Skype user " + username + " not found");
            }

            final SearchResult result = answer.next();
            final Rdn[] userRDN = getRelativeDNFromResult(result);

            // Make sure there are no more search results. If there are, then
            // the username isn't unique on the LDAP server (a perfectly possible
            // scenario since only fully qualified dn's need to be unqiue).
            // There really isn't a way to handle this, so throw an exception.
            // The baseDN must be set correctly so that this doesn't happen.
            if (answer.hasMoreElements()) {
                Log.debug("Search for userDN based on hybrid username '{}' found multiple responses, throwing exception.", username);
                throw new UserNotFoundException("LDAP hybrid username lookup for " + username + " matched multiple entries.");
            }
            // Close the enumeration.
            answer.close();

            return userRDN;
        } catch (final UserNotFoundException e) {
            Log.trace("UserNotFoundException thrown when searching for hybrid username '{}'", username, e);
            throw e;
        } catch (final Exception e) {
            Log.debug("Exception thrown when searching for userDN based on hybrid username '{}'", username, e);
            throw e;
        }
        finally {
            try { if ( ctx != null ) { ctx.close(); } }
            catch (Exception e) {
                Log.debug("An unexpected exception occurred while closing the LDAP context after searching for Skype user '{}'.", username, e);
            }
        }
    }

    private static class DNCacheEntry implements Serializable
    {
        private final Rdn[] userRDN; // relative to baseDN!
        private final LdapName baseDN;

        public DNCacheEntry( Rdn[] userRDN, LdapName baseDN )
        {
            if ( userRDN == null ) {
                throw new IllegalArgumentException("Argument 'userRDN' cannot be null.");
            }

            if ( baseDN == null ) {
                throw new IllegalArgumentException("Argument 'baseDN' cannot be null.");
            }
            this.userRDN = userRDN;
            this.baseDN = baseDN;
        }

        public Rdn[] getUserRDN()
        {
            return userRDN;
        }

        public LdapName getBaseDN()
        {
            return baseDN;
        }

        @Override
        public boolean equals( final Object o )
        {
            if ( this == o ) { return true; }
            if ( o == null || getClass() != o.getClass() ) { return false; }
            final SkypeUsernameProvider.DNCacheEntry that = (SkypeUsernameProvider.DNCacheEntry) o;
            return Arrays.equals(userRDN, that.userRDN) &&
                    baseDN.equals(that.baseDN);
        }

        @Override
        public int hashCode()
        {
            int result = Objects.hash(baseDN);
            result = 31 * result + Arrays.hashCode(userRDN);
            return result;
        }
    }
}