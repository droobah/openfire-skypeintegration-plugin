<%@ page
   import="org.jivesoftware.openfire.XMPPServer,
           org.igniterealtime.openfire.plugins.skypeintegration.SkypeIntegrationPlugin,
           org.jivesoftware.util.CookieUtils,
           org.jivesoftware.util.ParamUtils,
           org.jivesoftware.util.StringUtils,
           java.util.HashMap"
	errorPage="error.jsp"%>
<%@ page import="java.util.Map" %>

<%@ taglib uri="admin" prefix="admin" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>

<%
    final boolean save = request.getParameter( "save" ) != null;

    final Cookie csrfCookie = CookieUtils.getCookie( request, "csrf" );
    final String csrfParam = ParamUtils.getParameter( request, "csrf" );
    final String exampleText = ParamUtils.getParameter( request, "exampletext" );

    final SkypeIntegrationPlugin plugin = (SkypeIntegrationPlugin) XMPPServer.getInstance().getPluginManager().getPlugin( "skypeintegration" );

    final Map<String, String> errors = new HashMap<>();
    if ( save )
    {
        // CSRF has to be done manually.
        if ( csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals( csrfParam ) )
        {
            errors.put( "csrf", "CSRF Failure!" );
        }

        if ( exampleText == null || exampleText.isEmpty() )
        {
            errors.put( "exampleText", "" );
        }

        if ( errors.isEmpty() )
        {
            response.sendRedirect( "skype-integration-settings.jsp?settingsSaved=true" );
            return;
        }
    }

    final String csrf = StringUtils.randomString( 15 );
    CookieUtils.setCookie( request, response, "csrf", csrf, -1 );

    pageContext.setAttribute( "csrf", csrf );
    pageContext.setAttribute( "errors", errors );
    pageContext.setAttribute( "exampleText", exampleText );
%>

<html>
	<head>
	  <title><fmt:message key="skypeintegration.title" /></title>
	  <meta name="pageID" content="skype-integration-settings"/>
	</head>
	<body>

	<c:choose>
		<c:when test="${not empty param.settingsSaved and empty errors}">
			<admin:infoBox type="success"><fmt:message key="skypeintegration.saved.success" /></admin:infoBox>
		</c:when>
		<c:otherwise>
			<c:forEach var="err" items="${errors}">
				<admin:infobox type="error">
					<c:choose>
						<c:when test="${err.key eq 'exampleText'}"><fmt:message key="skypeintegration.text.missing"/></c:when>
						<c:otherwise>
							<c:if test="${not empty err.value}">
								<c:out value="${err.value}"/>
							</c:if>
							(<c:out value="${err.key}"/>)
						</c:otherwise>
					</c:choose>
				</admin:infobox>
			</c:forEach>
		</c:otherwise>
	</c:choose>

	<p><fmt:message key="skypeintegration.directions" /></p>

	<form action="skype-integration-settings.jsp?save" method="post">

        <fmt:message key="skypeintegration.options" var="boxtitle"/>
		<admin:contentBox title="${boxtitle}">

			<table cellpadding="3" cellspacing="0" border="0" width="100%">
				<tr>
					<td width="5%" valign="top"><fmt:message key="skypeintegration.text_label" />:&nbsp;*</td>
					<td width="95%"><textarea cols="120" rows="20" wrap="virtual" name="exampletext"><c:out value="${exampleText}"/></textarea></td>
				</tr>
				<tr>
					<td colspan="2" style="padding-top: 10px"><input type="submit" value="<fmt:message key="skypeintegration.button.save" />"/></td>
				</tr>
			</table>

		</admin:contentBox>

		<span class="jive-description">
			* <fmt:message key="skypeintegration.required" />
        </span>

        <input type="hidden" name="csrf" value="${csrf}">

    </form>

</body>
</html>